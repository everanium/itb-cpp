/*
 * The final summary in both renderings, and the two measurements it
 * folds in that are not per-worker counters: the process resident
 * set and the shared library's pool counters.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "loop.hpp"

namespace loop {

namespace {

/* Parses one "Vm...:   1234 kB" line of /proc/self/status into
 * bytes; zero on any parse failure. */
std::uint64_t status_kb(const std::string &line)
{
    const std::size_t colon = line.find(':');
    if (colon == std::string::npos) {
        return 0;
    }
    const unsigned long long kb = std::strtoull(line.c_str() + colon + 1, nullptr, 10);
    return static_cast<std::uint64_t>(kb) * 1024u;
}

/* The differenced pool figures of one run. */
struct PoolDelta {
    std::int64_t tiers = 0;
    std::vector<std::int64_t> starter;
    std::vector<std::int64_t> get;
    std::vector<std::int64_t> fresh;
    std::vector<std::int64_t> regrow;
    std::vector<std::int64_t> new_bytes;
    std::int64_t buf_get = 0, buf_new = 0, buf_regrow = 0, buf_regrow_bytes = 0;
    std::int64_t chunk_get = 0, chunk_new = 0, chunk_regrow = 0, chunk_regrow_bytes = 0;
};

void pool_diff(const RunState &r, PoolDelta &d)
{
    if (r.pool_warmup.size() < 9 || r.pool_steady.size() != r.pool_warmup.size()) {
        return;
    }
    const std::vector<std::int64_t> &w = r.pool_warmup;
    const std::vector<std::int64_t> &s = r.pool_steady;
    const std::int64_t tiers = s[0];
    if (tiers < 0 || tiers > 64
        || static_cast<std::size_t>(1 + 5 * tiers + 8) > s.size()) {
        return;
    }
    d.tiers = tiers;
    d.starter.resize(static_cast<std::size_t>(tiers));
    d.get.resize(static_cast<std::size_t>(tiers));
    d.fresh.resize(static_cast<std::size_t>(tiers));
    d.regrow.resize(static_cast<std::size_t>(tiers));
    d.new_bytes.resize(static_cast<std::size_t>(tiers));
    for (std::int64_t i = 0; i < tiers; i++) {
        const std::size_t base = static_cast<std::size_t>(1 + 5 * i);
        const std::size_t k = static_cast<std::size_t>(i);
        d.starter[k] = s[base + 0];
        d.get[k] = s[base + 1] - w[base + 1];
        d.fresh[k] = s[base + 2] - w[base + 2];
        d.regrow[k] = s[base + 3] - w[base + 3];
        d.new_bytes[k] = s[base + 4] - w[base + 4];
    }
    const std::size_t tail = static_cast<std::size_t>(1 + 5 * tiers);
    d.buf_get = s[tail + 0] - w[tail + 0];
    d.buf_new = s[tail + 1] - w[tail + 1];
    d.buf_regrow = s[tail + 2] - w[tail + 2];
    d.buf_regrow_bytes = s[tail + 3] - w[tail + 3];
    d.chunk_get = s[tail + 4] - w[tail + 4];
    d.chunk_new = s[tail + 5] - w[tail + 5];
    d.chunk_regrow = s[tail + 6] - w[tail + 6];
    d.chunk_regrow_bytes = s[tail + 7] - w[tail + 7];
}

/* Misses over checkouts as a percentage; zero when nothing was
 * checked out. */
double miss_percent(std::int64_t miss, std::int64_t get)
{
    if (get <= 0) {
        return 0.0;
    }
    return 100.0 * static_cast<double>(miss) / static_cast<double>(get);
}

/* Writes s as a JSON string literal with the escapes JSON requires. */
std::string json_string(std::string_view s)
{
    std::string out("\"");
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                out += fmt("\\u%04x", static_cast<unsigned>(c));
            } else {
                out.push_back(ch);
            }
        }
    }
    out.push_back('"');
    return out;
}

/* The effective GC percentage as the runtime reports it: the query
 * form of the setter (a set-and-restore round trip inside the
 * library) so the field is the same whether the value came from the
 * flag, the environment, or the runtime default. */
int effective_gogc(int flag)
{
    if (flag > 0) {
        return flag;
    }
    return itb::set_gc_percent(-1);
}

} // namespace

/* The process's current resident set and its high-water mark in
 * bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
 * Both are zero on a platform without that file; the figures are
 * informational and never enter the verdict. */
void read_rss(std::uint64_t &current, std::uint64_t &peak)
{
    current = 0;
    peak = 0;
    std::ifstream f("/proc/self/status");
    if (!f) {
        return;
    }
    std::string line;
    while (std::getline(f, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) {
            current = status_kb(line);
        } else if (line.compare(0, 6, "VmHWM:") == 0) {
            peak = status_kb(line);
        }
    }
}

/* Pool counters. The shared library keeps process-wide monotonic
 * totals at every pool checkout of its cipher core: per hash-array
 * tier the starter width, checkouts, constructor misses, regrow
 * replacements and bytes allocated; for the scratch byte pool and
 * the parallax chunk pool the checkouts, constructor misses, regrows
 * and regrow bytes. Two snapshots bracketing the main loop are
 * differenced into per-run hit / miss figures that tell whether a
 * pool keeps its items warm between calls or evicts them across GC
 * cycles. The slot layout is read from the library: slot 0 carries
 * the tier count T, tier i occupies the five slots at 1 + 5*i, and
 * the two byte pools occupy the eight slots at 1 + 5*T; the buffer
 * is sized from the binding's length query, never from a constant. */
bool pool_snapshot_alloc(std::vector<std::int64_t> &dst)
{
    const std::size_t slots = itb::pool_stats_len();
    if (slots == 0) {
        return false;
    }
    dst.assign(slots, 0);
    return true;
}

bool pool_snapshot_take(std::vector<std::int64_t> &dst)
{
    try {
        (void)itb::pool_stats(dst);
    } catch (const itb::Error &) {
        return false;
    }
    return true;
}

/* Output contract. Both renderings are shared with the Go harness and
 * every other binding's loop utility field for field: the same lines
 * in the same order, the same keys in the same order, floats with a
 * fixed number of decimals so the JSON is byte-identical across
 * implementations. The Go harness alone adds its runtime-internal
 * lines after rss: and its runtime-internal keys after
 * parallax_chunk_pool; nothing here reproduces them because nothing
 * they read is reachable through the C ABI. */
int final_summary(RunState &r, std::int64_t elapsed_ns)
{
    const Config &cfg = r.cfg;
    std::int64_t total_iters = 0;
    std::int64_t total_enc = 0;
    std::int64_t total_dec = 0;
    std::int64_t nanos_enc = 0;
    std::int64_t nanos_dec = 0;
    int errors = 0;
    for (int i = 0; i < cfg.workers; i++) {
        const Worker &w = r.workers[static_cast<std::size_t>(i)];
        total_iters += w.iters.load();
        total_enc += w.bytes_enc.load();
        total_dec += w.bytes_dec.load();
        nanos_enc += w.nanos_enc.load();
        nanos_dec += w.nanos_dec.load();
        if (w.failed) {
            errors++;
        }
    }

    /* Throughput. Per-direction throughput divides the sum of every
     * worker's wall time in that direction by the worker count — the
     * equivalent single-stream wall time under N-way concurrency — so
     * each direction reports the aggregate rate it sustained rather
     * than collapsing to combined/2 (every iteration moves equal
     * encrypt and decrypt bytes, so a total-elapsed denominator would
     * give both directions the same figure). The combined rate keeps
     * total elapsed as the one-glance overall figure. */
    const std::int64_t avg_enc = nanos_enc > 0 ? nanos_enc / cfg.workers : 0;
    const std::int64_t avg_dec = nanos_dec > 0 ? nanos_dec / cfg.workers : 0;

    const std::int64_t rss_delta =
        static_cast<std::int64_t>(r.rss_final) - static_cast<std::int64_t>(r.rss_warmup);
    double rss_growth = 0.0;
    if (r.rss_warmup > 0) {
        rss_growth = 100.0 * static_cast<double>(rss_delta) / static_cast<double>(r.rss_warmup);
    }

    PoolDelta pd;
    pool_diff(r, pd);

    const bool pass = errors == 0;
    const long long rekeys = static_cast<long long>(r.rekeys.load());
    const long long cycles = static_cast<long long>(r.blob_cycles.load());
    const int gomaxprocs = itb::set_gomaxprocs(0);
    const std::string stream_profile = r.stream_pipe.has_value() ? r.stream_profile : "";
    const std::string msg_profile = r.msg_pipe.has_value() ? r.msg_profile : "";

    if (cfg.json_output) {
        std::string j = fmt("{\"duration_seconds\":%.3f", static_cast<double>(elapsed_ns) / 1e9);
        j += fmt(",\"iterations\":%lld", static_cast<long long>(total_iters));
        j += ",\"per_worker_iterations\":[";
        for (int i = 0; i < cfg.workers; i++) {
            j += fmt("%s%lld", i > 0 ? "," : "",
                     static_cast<long long>(r.workers[static_cast<std::size_t>(i)].iters.load()));
        }
        j += "]";
        j += fmt(",\"bytes_encrypted\":%lld", static_cast<long long>(total_enc));
        j += fmt(",\"bytes_decrypted\":%lld", static_cast<long long>(total_dec));
        j += fmt(",\"encrypt_mb_per_sec\":%.1f", mb_per_sec(total_enc, avg_enc));
        j += fmt(",\"decrypt_mb_per_sec\":%.1f", mb_per_sec(total_dec, avg_dec));
        j += fmt(",\"combined_mb_per_sec\":%.1f", mb_per_sec(total_enc + total_dec, elapsed_ns));
        j += fmt(",\"rekeys\":%lld", rekeys);
        j += fmt(",\"blob_cycles\":%lld", cycles);
        j += ",\"worker_errors\":[";
        {
            int n = 0;
            for (int i = 0; i < cfg.workers; i++) {
                const Worker &w = r.workers[static_cast<std::size_t>(i)];
                if (w.failed) {
                    if (n++ > 0) {
                        j += ",";
                    }
                    j += json_string(w.error);
                }
            }
        }
        j += "]";
        j += fmt(",\"verdict\":\"%s\"", pass ? "PASS" : "FAIL");
        j += fmt(",\"shape\":\"%s\"", shape_name(cfg.shape));
        j += ",\"stream_profile\":" + json_string(stream_profile);
        j += ",\"message_profile\":" + json_string(msg_profile);
        j += ",\"hash\":" + json_string(cfg.hash);
        j += ",\"mac\":" + json_string(cfg.mac);
        j += fmt(",\"payload_bytes\":%lld", static_cast<long long>(cfg.payload));
        j += fmt(",\"payload_mode\":\"%s\"", payload_mode_name(cfg.payload_mode));
        j += fmt(",\"seed\":%llu", static_cast<unsigned long long>(cfg.seed));
        j += fmt(",\"key_bits\":%d", cfg.key_bits);
        j += fmt(",\"nonce_bits\":%d", cfg.nonce_bits);
        j += fmt(",\"blob_mode\":%d", cfg.blob_mode);
        j += ",\"drbg\":" + json_string(cfg.drbg);
        std::string auto_tier;
        try {
            auto_tier = itb::drbg_auto_tier();
        } catch (const itb::Error &) {
            auto_tier.clear();
        }
        j += ",\"drbg_auto_tier\":" + json_string(auto_tier);
        j += fmt(",\"chunk_size_bytes\":%lld", static_cast<long long>(cfg.chunk_size));
        j += fmt(",\"barrier_fill\":%d", cfg.barrier_fill);
        j += fmt(",\"parallax\":\"%s\"", on_off(cfg.parallax));
        j += fmt(",\"wrapper\":\"%s\"", on_off(cfg.wrapper));
        j += fmt(",\"goroutines_requested\":%d", cfg.workers_requested);
        j += fmt(",\"goroutines\":%d", cfg.workers);
        j += fmt(",\"concurrency\":\"%s\"", kConcurrency);
        j += fmt(",\"gogc\":\"%d\"", effective_gogc(cfg.gogc));
        j += fmt(",\"memlimit_bytes\":%lld", static_cast<long long>(cfg.memlimit));
        j += fmt(",\"gomaxprocs\":%d", gomaxprocs);
        j += ",\"microbatch_tiers\":" + json_string(policy_label(std::getenv("ITB_MICROBATCH_TIERS")));
        j += ",\"hashpool_starters\":" + json_string(policy_label(std::getenv("ITB_HASHPOOL_STARTERS")));
        j += fmt(",\"rss_warmup_bytes\":%llu", static_cast<unsigned long long>(r.rss_warmup));
        j += fmt(",\"rss_peak_bytes\":%llu", static_cast<unsigned long long>(r.rss_peak));
        j += fmt(",\"rss_final_bytes\":%llu", static_cast<unsigned long long>(r.rss_final));
        j += fmt(",\"rss_growth_percent\":%.2f", rss_growth);
        j += ",\"hash_pool_tiers\":[";
        {
            int n = 0;
            for (std::int64_t i = 0; i < pd.tiers; i++) {
                const std::size_t k = static_cast<std::size_t>(i);
                if (pd.starter[k] == 0) {
                    continue;
                }
                j += fmt("%s{\"tier\":%lld,\"starter\":%lld,\"get\":%lld,\"new\":%lld,"
                         "\"regrow\":%lld,\"new_bytes\":%lld,\"miss_percent\":%.2f}",
                         n++ > 0 ? "," : "", static_cast<long long>(i),
                         static_cast<long long>(pd.starter[k]), static_cast<long long>(pd.get[k]),
                         static_cast<long long>(pd.fresh[k]), static_cast<long long>(pd.regrow[k]),
                         static_cast<long long>(pd.new_bytes[k]),
                         miss_percent(pd.fresh[k] + pd.regrow[k], pd.get[k]));
            }
        }
        j += "]";
        j += fmt(",\"buf_pool\":{\"get\":%lld,\"new\":%lld,\"regrow\":%lld,\"regrow_bytes\":%lld,"
                 "\"miss_percent\":%.2f}",
                 static_cast<long long>(pd.buf_get), static_cast<long long>(pd.buf_new),
                 static_cast<long long>(pd.buf_regrow),
                 static_cast<long long>(pd.buf_regrow_bytes),
                 miss_percent(pd.buf_regrow, pd.buf_get));
        j += fmt(",\"parallax_chunk_pool\":{\"get\":%lld,\"new\":%lld,\"regrow\":%lld,"
                 "\"regrow_bytes\":%lld,\"miss_percent\":%.2f}",
                 static_cast<long long>(pd.chunk_get), static_cast<long long>(pd.chunk_new),
                 static_cast<long long>(pd.chunk_regrow),
                 static_cast<long long>(pd.chunk_regrow_bytes),
                 miss_percent(pd.chunk_regrow, pd.chunk_get));
        j += "}\n";
        std::fwrite(j.data(), 1, j.size(), stdout);
        std::fflush(stdout);
        return pass ? 0 : 1;
    }

    log_line("=== FINAL ===");
    log_line("  duration: " + human_duration((elapsed_ns + 500000) / 1000000 * 1000000));
    {
        std::string parts;
        for (int i = 0; i < cfg.workers; i++) {
            parts += fmt("%s%lld", i > 0 ? " + " : "",
                         static_cast<long long>(r.workers[static_cast<std::size_t>(i)].iters.load()));
        }
        log_line(fmt("  iterations: %s = %lld total", parts.c_str(),
                     static_cast<long long>(total_iters)));
    }
    log_line(fmt("  throughput: encrypt %s, decrypt %s, combined %s",
                 human_rate(total_enc, avg_enc).c_str(),
                 human_rate(total_dec, avg_dec).c_str(),
                 human_rate(total_enc + total_dec, elapsed_ns).c_str()));
    log_line(fmt("  bytes: %s encrypted, %s decrypted",
                 human_bytes(total_enc).c_str(), human_bytes(total_dec).c_str()));
    log_line(fmt("  data integrity: %lld/%lld PASS", static_cast<long long>(total_iters),
                 static_cast<long long>(total_iters)));
    log_line(fmt("  concurrency: %s, workers %d (requested %d)", kConcurrency,
                 cfg.workers, cfg.workers_requested));
    log_line(fmt("  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)",
                 human_bytes(static_cast<std::int64_t>(r.rss_warmup)).c_str(),
                 human_bytes(static_cast<std::int64_t>(r.rss_peak)).c_str(),
                 human_bytes(static_cast<std::int64_t>(r.rss_final)).c_str(),
                 human_bytes_signed(rss_delta).c_str(), rss_growth));
    for (std::int64_t i = 0; i < pd.tiers; i++) {
        const std::size_t k = static_cast<std::size_t>(i);
        if (pd.starter[k] == 0) {
            continue;
        }
        log_line(fmt("  hash pool tier %lld (starter %lld): get %lld, miss %lld "
                     "(new %lld + regrow %lld), miss %.2f%%, %s allocated",
                     static_cast<long long>(i), static_cast<long long>(pd.starter[k]),
                     static_cast<long long>(pd.get[k]),
                     static_cast<long long>(pd.fresh[k] + pd.regrow[k]),
                     static_cast<long long>(pd.fresh[k]), static_cast<long long>(pd.regrow[k]),
                     miss_percent(pd.fresh[k] + pd.regrow[k], pd.get[k]),
                     human_bytes(pd.new_bytes[k]).c_str()));
    }
    log_line(fmt("  buf pool: get %lld, regrow %lld (of which fresh %lld), miss %.2f%%, %s regrown",
                 static_cast<long long>(pd.buf_get), static_cast<long long>(pd.buf_regrow),
                 static_cast<long long>(pd.buf_new), miss_percent(pd.buf_regrow, pd.buf_get),
                 human_bytes(pd.buf_regrow_bytes).c_str()));
    log_line(fmt("  parallax chunk pool: get %lld, regrow %lld (of which fresh %lld), "
                 "miss %.2f%%, %s regrown",
                 static_cast<long long>(pd.chunk_get), static_cast<long long>(pd.chunk_regrow),
                 static_cast<long long>(pd.chunk_new),
                 miss_percent(pd.chunk_regrow, pd.chunk_get),
                 human_bytes(pd.chunk_regrow_bytes).c_str()));
    if (rekeys > 0) {
        log_line(fmt("  rekeys: %lld", rekeys));
    }
    if (cycles > 0) {
        log_line(fmt("  blob cycles: %lld", cycles));
    }
    for (int i = 0; i < cfg.workers; i++) {
        const Worker &w = r.workers[static_cast<std::size_t>(i)];
        if (w.failed) {
            log_line("  ERROR: " + w.error);
        }
    }
    if (pass) {
        log_line("  verdict: PASS");
        return 0;
    }
    log_line(fmt("  verdict: FAIL (errors=%d)", errors));
    return 1;
}

} // namespace loop
