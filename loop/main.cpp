/*
 * Long-run stress harness. The loop utility holds one Pipeline handle
 * per exercised cipher surface for minutes, hammers it with
 * concurrent encrypt -> decrypt -> compare round-trips from N worker
 * threads, rotates the outer masters and reopens the handle from its
 * session blob on a schedule, and reports whether the process
 * survived with every byte intact. It is the C++ binding's
 * counterpart of the Go harness under tools/loop: the same flags, the
 * same round structure, the same summary in both renderings.
 *
 * The default shape is full production: the Streaming AEAD profile
 * with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
 * inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
 * driven through a stream session by three workers for five minutes
 * on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
 * plaintext held for the whole run, so any cross-call state leakage
 * inside the Pipeline surfaces as a data mismatch between workers
 * rather than cancelling out.
 *
 * A failure is one of two things. A cipher, rekey or load call that
 * returns a non-OK status is a worker error: the run stops, the
 * summary lists it, the verdict is FAIL and the exit code 1. A
 * round-trip that returns without error but with different bytes is
 * a data mismatch: the process terminates on the spot with exit
 * code 3, printing the worker, the iteration and the first differing
 * offset, and no summary — the state that produced the wrong bytes
 * is the evidence. A crash inside the shared library or the host
 * runtime has no exit code of its own here; surfacing it is what the
 * utility is for.
 *
 * Usage:
 *
 *   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
 *          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
 *          --parallax on --wrapper on
 *
 * Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
 * then the partial summary prints.
 */

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "loop.hpp"

namespace loop {

namespace {

/* Profiles the shape-based pair is built against when --profile is
 * empty. */
constexpr const char *kDefaultStreamProfile = "streaming-aead-triple-mac-v1";
constexpr const char *kDefaultMessageProfile = "singlemsg-triple-mac-v1";

/* The primitive supplied for the parallax palette and the outer
 * cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
 * so it is sound outside the Interlocked Barrier, and it is the
 * closest relative of the AES-based inner primitive whose profiles
 * need this fill. */
constexpr const char *kKeystreamFillCipher = "aescmac";

/* ------------------------------------------------------------------ */
/* Flags                                                               */
/* ------------------------------------------------------------------ */

/* The raw flag values before validation. */
struct RawFlags {
    int barrier_fill = 0;
    std::int64_t blob_cycle_every = 0;
    int blob_mode = 1;
    std::string chunk_size = "0";
    std::string drbg;
    std::string duration = "5m";
    int gogc = 0;
    int gomaxprocs = 0;
    int goroutines = 3;
    std::string hash = "areion512";
    std::int64_t iterations = 0;
    bool json_output = false;
    int key_bits = 0;
    std::string mac = "hmac-blake3";
    std::string memlimit = "auto";
    std::string memprofile;
    int nonce_bits = 0;
    std::string parallax = "on";
    std::string payload_mode = "fixed";
    std::string payload_size = "16MB";
    std::string profile;
    std::int64_t rekey_every = 0;
    std::uint64_t seed = 0;
    std::string shape = "stream";
    std::string wrapper = "on";
};

/* One command-line flag: its name, the type label the usage prints,
 * the help text, the rendered default suffix, and the assignment that
 * lands the raw value in its slot. Values are validated after the
 * whole line is parsed. */
struct Flag {
    const char *name;
    const char *type_label;
    const char *help;
    bool boolean;
    std::string default_suffix;
    std::function<bool(std::string_view)> assign;
};

bool parse_int(std::string_view v, int &slot)
{
    const std::string s(v);
    if (s.empty()) {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const long n = std::strtol(s.c_str(), &end, 10);
    if (*end != '\0' || errno != 0 || n > 2147483647L || n < -2147483647L) {
        return false;
    }
    slot = static_cast<int>(n);
    return true;
}

bool parse_int64(std::string_view v, std::int64_t &slot)
{
    const std::string s(v);
    if (s.empty()) {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const long long n = std::strtoll(s.c_str(), &end, 10);
    if (*end != '\0' || errno != 0) {
        return false;
    }
    slot = static_cast<std::int64_t>(n);
    return true;
}

bool parse_uint64(std::string_view v, std::uint64_t &slot)
{
    const std::string s(v);
    if (s.empty() || s[0] == '-') {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const unsigned long long n = std::strtoull(s.c_str(), &end, 10);
    if (*end != '\0' || errno != 0) {
        return false;
    }
    slot = static_cast<std::uint64_t>(n);
    return true;
}

/* The flag table, in alphabetical order (the order the usage prints).
 * The default suffix is rendered from the slot while it still holds
 * its default, so the usage can never disagree with the value the
 * parse starts from. */
std::vector<Flag> flag_table(RawFlags &f)
{
    std::vector<Flag> t;
    const auto add_int = [&t](const char *name, int &slot, const char *help) {
        t.push_back({ name, "int", help, false,
                      slot != 0 ? fmt(" (default %d)", slot) : std::string(),
                      [&slot](std::string_view v) { return parse_int(v, slot); } });
    };
    const auto add_int64 = [&t](const char *name, std::int64_t &slot, const char *help) {
        t.push_back({ name, "int", help, false, std::string(),
                      [&slot](std::string_view v) { return parse_int64(v, slot); } });
    };
    const auto add_uint64 = [&t](const char *name, std::uint64_t &slot, const char *help) {
        t.push_back({ name, "uint", help, false, std::string(),
                      [&slot](std::string_view v) { return parse_uint64(v, slot); } });
    };
    const auto add_string = [&t](const char *name, const char *label, std::string &slot,
                                 const char *help) {
        t.push_back({ name, label, help, false,
                      slot.empty() ? std::string() : fmt(" (default \"%s\")", slot.c_str()),
                      [&slot](std::string_view v) { slot.assign(v); return true; } });
    };
    const auto add_bool = [&t](const char *name, bool &slot, const char *help) {
        t.push_back({ name, "", help, true, std::string(),
                      [&slot](std::string_view v) {
                          if (v == "true") {
                              slot = true;
                          } else if (v == "false") {
                              slot = false;
                          } else {
                              return false;
                          }
                          return true;
                      } });
    };

    add_int("barrier-fill", f.barrier_fill,
            "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)");
    add_int64("blob-cycle-every", f.blob_cycle_every,
              "reopen each pipeline from its session blob every N iterations per worker; 0 = never");
    add_int("blob-mode", f.blob_mode,
            "container floor sizing mode: 1 (per-region, default) | 2 (per-container)");
    add_string("chunk-size", "string", f.chunk_size,
               "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape");
    add_string("drbg", "string", f.drbg,
               "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)");
    add_string("duration", "duration", f.duration,
               "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0");
    add_int("gogc", f.gogc, "GC trigger percentage; 0 = leave the runtime default");
    add_int("gomaxprocs", f.gomaxprocs,
            "Go runtime GOMAXPROCS override; 0 = inherit from the environment");
    add_int("goroutines", f.goroutines,
            "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1");
    add_string("hash", "string", f.hash, "inner ITB hash primitive name");
    add_int64("iterations", f.iterations,
              "fixed per-worker iteration count; 0 = duration-based");
    add_bool("json-output", f.json_output,
             "print the final summary as one compact JSON object instead of log lines");
    add_int("key-bits", f.key_bits,
            "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)");
    add_string("mac", "string", f.mac, "MAC primitive name");
    add_string("memlimit", "string", f.memlimit,
               "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)");
    add_string("memprofile", "string", f.memprofile,
               "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none");
    add_int("nonce-bits", f.nonce_bits,
            "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)");
    add_string("parallax", "string", f.parallax, "parallax layer: on | off");
    add_string("payload-mode", "string", f.payload_mode,
               "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii");
    add_string("payload-size", "string", f.payload_size,
               "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)");
    add_string("profile", "string", f.profile,
               "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair");
    add_int64("rekey-every", f.rekey_every,
              "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never");
    add_uint64("seed", f.seed,
               "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts");
    add_string("shape", "string", f.shape,
               "cipher surface to exercise: stream | message | stream_one_shot | both");
    add_string("wrapper", "string", f.wrapper, "wrapper layer: on | off");
    return t;
}

void usage(const std::vector<Flag> &table)
{
    std::string out("Usage of loop:\n");
    for (const Flag &fl : table) {
        out += fmt("  -%s%s%s\n", fl.name, fl.type_label[0] != '\0' ? " " : "", fl.type_label);
        out += fmt("    \t%s%s\n", fl.help, fl.default_suffix.c_str());
    }
    std::fwrite(out.data(), 1, out.size(), stderr);
    std::fflush(stderr);
}

/* Parses argv into the raw flag values. Accepts -name value,
 * --name value, -name=value and --name=value; a boolean flag takes
 * no value unless given as -name=true / -name=false. Returns 0, 1
 * for -h / --help (usage printed), or -1 after printing the error. */
int parse_argv(int argc, char **argv, const std::vector<Flag> &table)
{
    for (int i = 1; i < argc; i++) {
        const std::string_view arg(argv[i]);
        if (arg.size() < 2 || arg[0] != '-') {
            err_line(fmt("unexpected positional arguments: [%s]", argv[i]));
            return -1;
        }
        std::string_view name = arg.substr(arg[1] == '-' ? 2 : 1);
        if (name == "h" || name == "help") {
            usage(table);
            return 1;
        }
        std::string_view value;
        bool have_value = false;
        const std::size_t eq = name.find('=');
        if (eq != std::string_view::npos) {
            value = name.substr(eq + 1);
            have_value = true;
            name = name.substr(0, eq);
        }
        const Flag *fl = nullptr;
        for (const Flag &candidate : table) {
            if (name == candidate.name) {
                fl = &candidate;
                break;
            }
        }
        if (fl == nullptr) {
            err_line(fmt("flag provided but not defined: -%.*s",
                         static_cast<int>(name.size()), name.data()));
            usage(table);
            return -1;
        }
        if (!have_value) {
            if (fl->boolean) {
                value = "true";
            } else if (i + 1 < argc) {
                value = argv[++i];
            } else {
                err_line(fmt("flag needs an argument: -%s", fl->name));
                return -1;
            }
        }
        if (!fl->assign(value)) {
            err_line(fmt("invalid value \"%.*s\" for flag -%s",
                         static_cast<int>(value.size()), value.data(), fl->name));
            return -1;
        }
    }
    return 0;
}

/* Maps "on" / "off" to a bool; false otherwise. */
bool parse_on_off(std::string_view v, bool &out)
{
    if (v == "on") {
        out = true;
        return true;
    }
    if (v == "off") {
        out = false;
        return true;
    }
    return false;
}

/* Whether name is in the JSON array of strings the binding returns
 * for the shipped hash registry. Names are restricted to [a-z0-9-],
 * so a quoted run is one complete name. */
bool hash_registered(const std::string &name)
{
    try {
        const std::string json = itb::hash_names();
        return json.find("\"" + name + "\"") != std::string::npos;
    } catch (const itb::Error &) {
        return false;
    }
}

/* Folds a keystream primitive into opts for any layer the named
 * profile leaves unfilled but the operator asked for.
 *
 * A profile built around a primitive that is safe only inside the
 * Interlocked Barrier ships with no parallax palette and no outer
 * cipher: both layers run outside the barrier, where that primitive
 * would stand bare, so the recipe leaves them unnamed rather than
 * naming a primitive that must not key them. Engaging either layer
 * therefore needs a keystream-capable primitive supplied from
 * outside the recipe; without it construction fails on a palette
 * below its minimum or an unnamed outer cipher, and the primitive
 * that most deserves stressing becomes the one that cannot be
 * stressed with those layers engaged.
 *
 * Overrides fold into the resolved record the blob carries, so the
 * receiver rebuilds the same shape from the blob alone.
 *
 * C++-specific. The record is read as JSON text and the two keys are
 * probed by substring: an absent "palette" or "outer" key is the
 * unfilled state, since the encoder omits both when unset.
 *
 * Returns 1 when a layer was filled, 0 when none needed it, -1 on a
 * lookup failure (message already printed). */
int fill_keystream_layers(const std::string &name, itb::Opts &opts,
                          bool want_parallax, bool want_wrapper)
{
    std::string json;
    try {
        json = itb::lookup(name);
    } catch (const itb::Error &) {
        err_line(fmt("--profile \"%s\" is not a registered triple profile", name.c_str()));
        return -1;
    }
    int filled = 0;
    if (want_parallax && json.find("\"palette\":") == std::string::npos) {
        opts.set("parallaxPalette", std::string(kKeystreamFillCipher) + "," +
                                        kKeystreamFillCipher + "," + kKeystreamFillCipher);
        if (json.find("\"segment\":") == std::string::npos) {
            /* A recipe that never carried a palette never carried a
             * segment size either, and the schedule rejects zero. */
            opts.set("parallaxSegmentSize", "4093");
        }
        filled = 1;
    }
    if (want_wrapper && json.find("\"outer\":") == std::string::npos) {
        opts.set("outerCipher", kKeystreamFillCipher);
        filled = 1;
    }
    return filled;
}

/* Resolves a registered profile to the shape family its record's
 * mode exposes by reading the record through the binding's lookup:
 * a mode beginning with "streaming" exposes the stream surfaces, one
 * beginning with "singlemsg" the message surface, "blob-only" none.
 * Prints the validation message and returns false on rejection. */
bool profile_surface(const std::string &name, Shape &surface)
{
    std::string json;
    try {
        json = itb::lookup(name);
    } catch (const itb::Error &) {
        err_line(fmt("--profile \"%s\" is not a registered triple profile", name.c_str()));
        return false;
    }
    const std::string needle("\"mode\":\"");
    const std::size_t at = json.find(needle);
    if (at != std::string::npos) {
        const std::string_view mode = std::string_view(json).substr(at + needle.size());
        if (mode.substr(0, 9) == "streaming") {
            surface = Shape::Stream;
            return true;
        }
        if (mode.substr(0, 9) == "singlemsg") {
            surface = Shape::Message;
            return true;
        }
    }
    err_line(fmt("--profile \"%s\" carries no cipher surface (blob-only mode)", name.c_str()));
    return false;
}

/* Applies a --profile's surface to the requested shape: a
 * message-surface profile forces message; a stream-surface profile
 * keeps stream or stream_one_shot as requested and turns message or
 * both into stream. */
Shape narrow_shape(Shape requested, Shape surface)
{
    if (surface == Shape::Message) {
        return Shape::Message;
    }
    return requested == Shape::StreamOneShot ? Shape::StreamOneShot : Shape::Stream;
}

/* Builds the resolved config from argv. Returns 0, 1 for help, or
 * -1 after printing "loop: <message>" for the first failing rule. */
int parse_flags(int argc, char **argv, Config &cfg)
{
    RawFlags f;
    const std::vector<Flag> table = flag_table(f);
    const int rc = parse_argv(argc, argv, table);
    if (rc != 0) {
        return rc;
    }

    if (!parse_duration(f.duration, cfg.duration_ns) || cfg.duration_ns <= 0) {
        err_line(fmt("--duration must be positive, got %s", f.duration.c_str()));
        return -1;
    }
    cfg.iterations = f.iterations;
    if (cfg.iterations < 0) {
        err_line(fmt("--iterations must be >= 0, got %lld", static_cast<long long>(cfg.iterations)));
        return -1;
    }
    if (f.goroutines < 1 || f.goroutines > kMaxWorkers) {
        err_line(fmt("--goroutines must be in 1..%d, got %d", kMaxWorkers, f.goroutines));
        return -1;
    }
    /* Concurrency mode. This binding runs shared-handle: std::thread
     * workers call into one Pipeline handle concurrently, which the
     * shared library permits after construction, so --goroutines is
     * the thread count verbatim, never clamped. */
    cfg.workers_requested = f.goroutines;
    cfg.workers = f.goroutines;
    if (!parse_shape(f.shape, cfg.shape)) {
        err_line(fmt("--shape must be stream | message | stream_one_shot | both, got \"%s\"",
                     f.shape.c_str()));
        return -1;
    }
    if (!hash_registered(f.hash)) {
        err_line(fmt("--hash \"%s\" is not a registered hash primitive", f.hash.c_str()));
        return -1;
    }
    cfg.hash = f.hash;
    cfg.mac = f.mac; /* validated by Init: the C ABI enumerates no MAC names */
    if (!parse_size(f.payload_size, cfg.payload)) {
        err_line(fmt("--payload-size: invalid size \"%s\"", f.payload_size.c_str()));
        return -1;
    }
    if (cfg.payload < 1) {
        err_line("--payload-size must be at least 1 byte");
        return -1;
    }
    if (f.memlimit == "auto") {
        cfg.memlimit_auto = true;
        cfg.memlimit = cfg.workers <= 3 ? (std::int64_t{1} << 30) : (std::int64_t{256} << 20);
    } else if (!parse_size(f.memlimit, cfg.memlimit)) {
        err_line(fmt("--memlimit: invalid size \"%s\"", f.memlimit.c_str()));
        return -1;
    }
    cfg.gogc = f.gogc;
    if (cfg.gogc < 0) {
        err_line(fmt("--gogc must be >= 0, got %d", cfg.gogc));
        return -1;
    }
    if (!parse_on_off(f.parallax, cfg.parallax)) {
        err_line(fmt("--parallax must be on | off, got \"%s\"", f.parallax.c_str()));
        return -1;
    }
    if (!parse_on_off(f.wrapper, cfg.wrapper)) {
        err_line(fmt("--wrapper must be on | off, got \"%s\"", f.wrapper.c_str()));
        return -1;
    }
    cfg.profile = f.profile;
    if (!cfg.profile.empty()) {
        Shape surface = Shape::Stream;
        if (!profile_surface(cfg.profile, surface)) {
            return -1;
        }
        cfg.shape = narrow_shape(cfg.shape, surface);
    }
    cfg.key_bits = f.key_bits;
    switch (cfg.key_bits) {
    case 0: case 512: case 1024: case 2048:
        break;
    default:
        err_line(fmt("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d",
                     cfg.key_bits));
        return -1;
    }
    cfg.nonce_bits = f.nonce_bits;
    switch (cfg.nonce_bits) {
    case 0: case 128: case 256: case 512:
        break;
    default:
        err_line(fmt("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d",
                     cfg.nonce_bits));
        return -1;
    }
    cfg.blob_mode = f.blob_mode;
    switch (cfg.blob_mode) {
    case 1: case 2:
        break;
    default:
        err_line(fmt("--blob-mode must be 1 (per-region) | 2 (per-container), got %d",
                     cfg.blob_mode));
        return -1;
    }
    cfg.barrier_fill = f.barrier_fill;
    switch (cfg.barrier_fill) {
    case 0: case 1: case 2: case 4: case 8: case 16: case 32:
        break;
    default:
        err_line(fmt("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d",
                     cfg.barrier_fill));
        return -1;
    }
    cfg.drbg = f.drbg; /* validated by Init: the C ABI enumerates no DRBG names */
    if (!parse_size(f.chunk_size, cfg.chunk_size)) {
        err_line(fmt("--chunk-size: invalid size \"%s\"", f.chunk_size.c_str()));
        return -1;
    }
    cfg.gomaxprocs = f.gomaxprocs;
    if (cfg.gomaxprocs < 0) {
        err_line(fmt("--gomaxprocs must be > 0 when specified, got %d", cfg.gomaxprocs));
        return -1;
    }
    cfg.rekey_every = f.rekey_every;
    if (cfg.rekey_every < 0) {
        err_line(fmt("--rekey-every must be >= 0, got %lld",
                     static_cast<long long>(cfg.rekey_every)));
        return -1;
    }
    cfg.blob_cycle_every = f.blob_cycle_every;
    if (cfg.blob_cycle_every < 0) {
        err_line(fmt("--blob-cycle-every must be >= 0, got %lld",
                     static_cast<long long>(cfg.blob_cycle_every)));
        return -1;
    }
    if (!parse_payload_mode(f.payload_mode, cfg.payload_mode)) {
        err_line(fmt("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"%s\"",
                     f.payload_mode.c_str()));
        return -1;
    }
    cfg.seed = f.seed;
    cfg.json_output = f.json_output;
    cfg.memprofile = f.memprofile;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Signals                                                             */
/* ------------------------------------------------------------------ */

volatile std::sig_atomic_t signal_seen = 0;

extern "C" void on_signal(int)
{
    signal_seen = 1;
}

/* Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
 * while it waits for the workers; it turns the flag into the stop
 * request every worker checks before starting an iteration, so a
 * signal interrupts nothing mid-call — the in-flight encrypt /
 * decrypt / compare completes, the worker returns, and the partial
 * summary prints with the verdict the completed iterations earned. */
void install_signals()
{
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

/* ------------------------------------------------------------------ */
/* Pipelines                                                           */
/* ------------------------------------------------------------------ */

/* Integer value of key in a profile JSON record; 0 when absent. */
long long record_int(const std::string &json, const char *key)
{
    const std::string needle = fmt("\"%s\":", key);
    const std::size_t at = json.find(needle);
    if (at == std::string::npos) {
        return 0;
    }
    return std::strtoll(json.c_str() + at + needle.size(), nullptr, 10);
}

/* String value of key in a profile JSON record, or "-" when absent
 * or empty. Profile record strings are restricted to [a-z0-9-], so a
 * quoted run is one complete value. */
std::string record_str(const std::string &json, const char *key)
{
    const std::string needle = fmt("\"%s\":\"", key);
    const std::size_t at = json.find(needle);
    if (at == std::string::npos) {
        return "-";
    }
    const std::size_t begin = at + needle.size();
    const std::size_t end = json.find('"', begin);
    if (end == std::string::npos || end == begin) {
        return "-";
    }
    return json.substr(begin, end - begin);
}

/* Boolean value of key in a profile JSON record; false when absent. */
bool record_bool(const std::string &json, const char *key)
{
    return json.find(fmt("\"%s\":true", key)) != std::string::npos;
}

/* Prints the construction line with the recipe read back from the
 * blob the Pipeline handed out, not echoed from the flags: every
 * construction override is proven to have reached the library by the
 * value the receiver would see. Record values that are empty (a No
 * MAC profile's MAC, a mixed profile's single hash) print as "-". */
void log_pipeline_initialised(const std::string &profile,
                              const std::vector<std::uint8_t> &blob)
{
    std::string json;
    try {
        json = itb::inspect(itb::as_bytes(blob));
    } catch (const itb::Error &) {
        log_line(fmt("pipeline initialised: profile=%s blob=%zu bytes (inspect: %s)",
                     profile.c_str(), blob.size(), itb::last_error().c_str()));
        return;
    }
    std::string line = fmt("pipeline initialised: profile=%s blob=%zu bytes hash=%s key-bits=%lld "
                           "nonce-bits=%lld barrier-fill=%lld chunk-size=%lld mac=%s parallax=%s wrapper=%s",
                           profile.c_str(), blob.size(), record_str(json, "hash").c_str(),
                           record_int(json, "keybits"), record_int(json, "nonce_bits"),
                           record_int(json, "barrier_fill"), record_int(json, "chunk"),
                           record_str(json, "mac").c_str(),
                           on_off(record_bool(json, "parallax")), on_off(record_bool(json, "wrapper")));
    const long long container_mode = record_int(json, "container_mode");
    if (container_mode == 2) {
        line += fmt(" container-mode=%lld", container_mode);
    }
    const std::string drbg = record_str(json, "drbg");
    if (drbg != "-") {
        line += " drbg=" + drbg;
    }
    log_line(line);
}

/* Sets the inner blob's "mode" field of a wrap-layer session blob to
 * target_mode (1 = per-region, 2 = per-container) in place. The wrap
 * layer's profile record carries its own "mode" (a string), so the
 * search starts at the inner blob ("ib"); both shipped modes are one
 * digit wide, so the blob length does not change and the key material
 * in blob is never copied. Returns false when the inner blob or its
 * mode field is not found. */
bool edit_inner_blob_mode(std::vector<std::uint8_t> &blob, int target_mode)
{
    const std::string_view text(reinterpret_cast<const char *>(blob.data()), blob.size());
    constexpr std::string_view ib_key = "\"ib\":{";
    constexpr std::string_view mode_key = "\"mode\":";
    const std::size_t ib = text.find(ib_key);
    if (ib == std::string_view::npos) {
        return false;
    }
    const std::size_t mode = text.find(mode_key, ib + ib_key.size());
    if (mode == std::string_view::npos) {
        return false;
    }
    const std::size_t at = mode + mode_key.size();
    if (at + 1 >= blob.size() || blob[at] < '1' || blob[at] > '2'
        || (blob[at + 1] >= '0' && blob[at + 1] <= '9')) {
        return false;
    }
    blob[at] = static_cast<std::uint8_t>('0' + target_mode);
    return true;
}

/* Constructs one Pipeline against profile with every flag-carried
 * override in the opts string (zero values included — the shared
 * library treats zero as "profile default"), then obtains the Init
 * blob once through save: the binding's init entry does not hand the
 * blob back, and the bytes are the ones Init produced. Later blob
 * reopens use the retained blob; save is never called again. */
bool build_pipeline(const Config &cfg, const std::string &profile,
                    std::optional<itb::Pipeline> &pipe, std::vector<std::uint8_t> &blob)
{
    itb::Opts opts;
    opts.set("innerHash", cfg.hash);
    opts.set("macName", cfg.mac);
    opts.set("withParallax", cfg.parallax ? "true" : "false");
    opts.set("withWrapper", cfg.wrapper ? "true" : "false");
    opts.set("keyBits", fmt("%d", cfg.key_bits));
    opts.set("nonceBits", fmt("%d", cfg.nonce_bits));
    opts.set("barrierFill", fmt("%d", cfg.barrier_fill));
    opts.set("drbg", cfg.drbg);
    opts.set("chunkSize", fmt("%lld", static_cast<long long>(cfg.chunk_size)));
    if (!cfg.profile.empty()) {
        const int filled = fill_keystream_layers(cfg.profile, opts, cfg.parallax, cfg.wrapper);
        if (filled < 0) {
            return false;
        }
        if (filled > 0) {
            err_line(fmt("%s leaves the requested keystream layers unnamed; %s supplied for them",
                         cfg.profile.c_str(), kKeystreamFillCipher));
        }
    }

    try {
        pipe = itb::Pipeline::init(profile, opts);
    } catch (const itb::Error &e) {
        err_line(fmt("Init(%s): %s", profile.c_str(), detail(e).c_str()));
        return false;
    }
    try {
        blob = pipe->save();
    } catch (const itb::Error &e) {
        err_line(fmt("Save(%s): %s", profile.c_str(), detail(e).c_str()));
        pipe.reset();
        return false;
    }
    if (cfg.blob_mode == 2) {
        /* The sizing mode is not an Opts knob: the Init blob is edited
         * and the pipeline reopened from it, so the retained blob (the
         * one blob-cycle reopens from) carries the edited mode. */
        if (!edit_inner_blob_mode(blob, 2)) {
            err_line("rewrite blob mode: inner blob mode field not found");
            pipe.reset();
            blob.clear();
            return false;
        }
        pipe.reset();
        try {
            pipe = itb::Pipeline::load(itb::as_bytes(blob));
        } catch (const itb::Error &e) {
            err_line(fmt("reload Mode 2 blob: %s", detail(e).c_str()));
            blob.clear();
            return false;
        }
    }
    log_pipeline_initialised(profile, blob);
    return true;
}

/* ------------------------------------------------------------------ */
/* Run                                                                 */
/* ------------------------------------------------------------------ */

int run(int argc, char **argv)
{
    RunState r;
    Config &cfg = r.cfg;
    const int rc = parse_flags(argc, argv, cfg);
    if (rc == 1) {
        return 0;
    }
    if (rc != 0) {
        return 2;
    }

    /* Runtime shaping. A long run under allocation churn grows the
     * Go heap inside the shared library without bound unless a soft
     * limit paces the collector, so a limit is always in force: an
     * explicit --memlimit is set as given, and auto caps the heap
     * only when the runtime reports no limit at all (a limit already
     * installed from the environment is left standing). The GC
     * percentage and GOMAXPROCS are set only when their flag is
     * non-zero — a zero flag skips the setter rather than calling it
     * with zero, because zero is a real value to the GC-percent
     * setter, and a call would clobber whatever the environment
     * installed. All of it lands before any Pipeline exists so the
     * baselines are taken under the shaped runtime. */
    if (cfg.memlimit_auto) {
        if (itb::set_memory_limit(-1) == INT64_MAX) {
            (void)itb::set_memory_limit(cfg.memlimit);
        }
    } else {
        (void)itb::set_memory_limit(cfg.memlimit);
    }
    cfg.memlimit = itb::set_memory_limit(-1);
    if (cfg.gogc > 0) {
        (void)itb::set_gc_percent(cfg.gogc);
    }
    if (cfg.gomaxprocs > 0) {
        (void)itb::set_gomaxprocs(cfg.gomaxprocs);
    }

    log_line(fmt("start: duration=%s iterations=%lld goroutines=%d workers=%d concurrency=%s "
                 "shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s",
                 human_duration(cfg.duration_ns).c_str(),
                 static_cast<long long>(cfg.iterations), cfg.workers_requested, cfg.workers,
                 kConcurrency, shape_name(cfg.shape), cfg.hash.c_str(), cfg.mac.c_str(),
                 human_bytes(cfg.payload).c_str(), human_bytes(cfg.memlimit).c_str(),
                 on_off(cfg.parallax), on_off(cfg.wrapper)));
    std::string overrides = fmt("overrides: profile=\"%s\" key-bits=%d nonce-bits=%d chunk-size=%s "
                                "barrier-fill=%d gomaxprocs=%d rekey-every=%lld blob-cycle-every=%lld "
                                "payload-mode=%s seed=%llu json-output=%s",
                                cfg.profile.c_str(), cfg.key_bits, cfg.nonce_bits,
                                human_bytes(cfg.chunk_size).c_str(), cfg.barrier_fill, cfg.gomaxprocs,
                                static_cast<long long>(cfg.rekey_every),
                                static_cast<long long>(cfg.blob_cycle_every),
                                payload_mode_name(cfg.payload_mode),
                                static_cast<unsigned long long>(cfg.seed),
                                cfg.json_output ? "true" : "false");
    if (cfg.blob_mode != 1) {
        overrides += fmt(" blob-mode=%d", cfg.blob_mode);
    }
    if (!cfg.drbg.empty()) {
        overrides += " drbg=" + cfg.drbg;
    }
    log_line(overrides);
    log_line(fmt("policy: microbatch-tiers=%s hashpool-starters=%s",
                 policy_label(std::getenv("ITB_MICROBATCH_TIERS")).c_str(),
                 policy_label(std::getenv("ITB_HASHPOOL_STARTERS")).c_str()));

    /* Pipeline construction — one shared handle per exercised shape.
     * stream and stream_one_shot share the streaming handle. */
    r.stream_profile = !cfg.profile.empty() ? cfg.profile : kDefaultStreamProfile;
    r.msg_profile = !cfg.profile.empty() ? cfg.profile : kDefaultMessageProfile;
    if (cfg.shape == Shape::Stream || cfg.shape == Shape::StreamOneShot
        || cfg.shape == Shape::Both) {
        if (!build_pipeline(cfg, r.stream_profile, r.stream_pipe, r.stream_blob)) {
            return 1;
        }
    }
    if (cfg.shape == Shape::Message || cfg.shape == Shape::Both) {
        if (!build_pipeline(cfg, r.msg_profile, r.msg_pipe, r.msg_blob)) {
            return 1;
        }
    }

    /* Allocation posture. Per-worker plaintexts are allocated once and
     * held for the whole run (rotating mode refills them in place per
     * iteration); the pump accumulators and the drain slice live
     * inside each worker and are reused across iterations; the message
     * and one-shot outputs are allocated by the binding per call and
     * released per iteration. Under the default fixed CSPRNG mode
     * every worker's buffer is distinct, so cross-worker data
     * crossover is detectable; pattern modes trade that property for
     * content edge-case coverage. */
    r.workers = std::vector<Worker>(static_cast<std::size_t>(cfg.workers));
    for (int i = 0; i < cfg.workers; i++) {
        Worker &w = r.workers[static_cast<std::size_t>(i)];
        w.id = i;
        w.run = &r;
        try {
            w.plaintext.resize(static_cast<std::size_t>(cfg.payload));
            w.scratch.resize(kPumpSlice);
        } catch (const std::bad_alloc &) {
            err_line("payload alloc: out of memory");
            return 1;
        }
        w.payload_mode = cfg.payload_mode;
        w.seeded = cfg.seed != 0;
        w.rng = seed_worker(cfg.seed, i);
        if (!fill_payload(cfg.payload_mode, w.seeded, w.rng, w.plaintext)) {
            err_line("payload fill: csprng");
            return 1;
        }
    }

    if (!pool_snapshot_alloc(r.pool_warmup) || !pool_snapshot_alloc(r.pool_steady)) {
        err_line("pool snapshot alloc failed");
        return 1;
    }

    install_signals();
    const auto participants = static_cast<std::ptrdiff_t>(cfg.workers) + 1;
    r.warmup_done = std::make_unique<std::barrier<>>(participants);
    r.release = std::make_unique<std::barrier<>>(participants);
    r.stop.store(false);
    r.active = cfg.workers;

    /* Warmup barrier. Every worker runs one iteration and waits; the
     * clock starts only once all of them have paid their first-call
     * costs (pool warm-up, lazy kernel dispatch, page faults on the
     * payload buffers), and the RSS and pool baselines taken here
     * describe a process that has already run the whole cipher path
     * once per worker. */
    const std::int64_t warmup_start = now_ns();
    for (int i = 0; i < cfg.workers; i++) {
        Worker &w = r.workers[static_cast<std::size_t>(i)];
        w.thread = std::thread(worker_main, &w);
    }
    r.warmup_done->arrive_and_wait();
    read_rss(r.rss_warmup, r.rss_peak);
    (void)pool_snapshot_take(r.pool_warmup);
    const std::int64_t warmup_ns = now_ns() - warmup_start;
    log_line(fmt("warmup: %d workers x 1 iter completed in %s (baseline rss=%s)", cfg.workers,
                 human_duration((warmup_ns + 50000000) / 100000000 * 100000000).c_str(),
                 human_bytes(static_cast<std::int64_t>(r.rss_warmup)).c_str()));

    /* Open the gate; the duration timer is a deadline the waiter
     * below enforces in duration mode. */
    r.start_ns = now_ns();
    r.finish_ns = r.start_ns;
    r.release->arrive_and_wait();

    /* Wait for every worker, polling every 100 ms so the deadline and
     * a signal are both noticed promptly. */
    {
        std::unique_lock<std::mutex> lk(r.done_mu);
        while (r.active > 0) {
            if (signal_seen != 0) {
                r.stop.store(true);
            }
            if (cfg.iterations == 0 && now_ns() - r.start_ns >= cfg.duration_ns) {
                r.stop.store(true);
            }
            r.done_cv.wait_for(lk, std::chrono::milliseconds(100));
        }
    }
    for (int i = 0; i < cfg.workers; i++) {
        r.workers[static_cast<std::size_t>(i)].thread.join();
    }
    const std::int64_t elapsed_ns = r.finish_ns - r.start_ns;
    read_rss(r.rss_final, r.rss_peak);
    (void)pool_snapshot_take(r.pool_steady);

    if (!cfg.memprofile.empty()) {
        try {
            itb::write_heap_profile(cfg.memprofile);
            log_line("memprofile: heap profile written to " + cfg.memprofile);
        } catch (const itb::Error &) {
            err_line("memprofile: " + itb::last_error());
        }
    }

    return final_summary(r, elapsed_ns);
}

} // namespace

/* C++-specific. printf-style composition into a std::string; the
 * format attribute keeps every call site checked by the compiler. */
std::string fmt(const char *f, ...)
{
    std::va_list ap;
    va_start(ap, f);
    std::va_list copy;
    va_copy(copy, ap);
    const int need = std::vsnprintf(nullptr, 0, f, copy);
    va_end(copy);
    std::string out;
    if (need > 0) {
        out.resize(static_cast<std::size_t>(need));
        (void)std::vsnprintf(out.data(), static_cast<std::size_t>(need) + 1, f, ap);
    }
    va_end(ap);
    return out;
}

/* Prints one prefixed status line to stdout. The text, its prefix and
 * its newline leave in one write: workers log concurrently during
 * maintenance, and a routine that emitted them separately would let
 * another worker's line land between the parts. */
void log_line(const std::string &text)
{
    const std::string line = "[loop] " + text + "\n";
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fflush(stdout);
}

/* The stderr counterpart, under the same one-write rule. */
void err_line(const std::string &text)
{
    const std::string line = "loop: " + text + "\n";
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
}

const char *on_off(bool b)
{
    return b ? "on" : "off";
}

/* Renders an encoder policy env value for the summary: the raw string
 * when set, "default" when the shipped ladder applies. */
std::string policy_label(const char *env)
{
    if (env == nullptr) {
        return "default";
    }
    std::string_view v(env);
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
        v.remove_prefix(1);
    }
    return v.empty() ? std::string("default") : std::string(v);
}

std::string detail(const itb::Error &e)
{
    return fmt("status %d: %s", static_cast<int>(e.status()), itb::last_error().c_str());
}

} // namespace loop

int main(int argc, char **argv)
{
    return loop::run(argc, argv);
}
