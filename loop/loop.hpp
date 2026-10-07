/*
 * Shared declarations of the loop stress harness: the resolved
 * configuration, the per-worker state, the run state every worker
 * shares, and the prototypes of the six units (main / ops / payload /
 * size / summary / worker).
 *
 * C++-specific. A header is how C++ shares declarations across
 * translation units; a language with modules or a single-file build
 * folds these into the units that own them.
 */

#ifndef ITB_LOOP_HPP
#define ITB_LOOP_HPP

#include <atomic>
#include <barrier>
#include <condition_variable>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "itb3.hpp"

namespace loop {

/* ------------------------------------------------------------------ */
/* Vocabulary                                                          */
/* ------------------------------------------------------------------ */

/* Cipher surfaces the --shape flag selects. */
enum class Shape {
    Stream,        /* session pump: begin / write / read / end */
    Message,       /* Single Message: one whole-buffer call    */
    StreamOneShot, /* stream surface, one whole-buffer call    */
    Both           /* all three, rotating by iteration number  */
};

/* Plaintext content policies the --payload-mode flag selects. */
enum class PayloadMode {
    Fixed,
    Rotating,
    PatternZero,
    PatternFF,
    PatternAscii
};

/* --goroutines ceiling; the harness targets modest hosts and each
 * worker pins payload-sized buffers for the whole run. */
inline constexpr int kMaxWorkers = 10;

/* The concurrency mode this binding implements, as the summary
 * reports it (shared-handle / independent-handles / single). */
inline constexpr const char *kConcurrency = "shared-handle";

/* Largest slice fed to a stream session per write; the drain after
 * every write uses the same bound. */
inline constexpr std::size_t kPumpSlice = std::size_t{1} << 20;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/* The resolved command line. */
struct Config {
    std::int64_t duration_ns = 0;  /* run duration; ignored when iterations > 0 */
    std::int64_t iterations = 0;   /* per-worker count incl. warmup; 0 = duration-based */
    int workers_requested = 0;     /* the --goroutines value as given */
    int workers = 0;               /* the effective worker count */
    Shape shape = Shape::Stream;
    std::string hash;
    std::string mac;
    std::int64_t payload = 0;      /* bytes per iteration */
    std::int64_t memlimit = 0;     /* resolved bytes; the effective limit once shaped */
    bool memlimit_auto = false;    /* --memlimit auto: cap only when the runtime has no limit */
    int gogc = 0;                  /* 0 = leave the runtime default */
    bool parallax = true;
    bool wrapper = true;

    std::string profile;           /* empty = shape-based profile pair */
    int key_bits = 0;              /* 0 = profile default */
    int nonce_bits = 0;            /* 0 = profile default */
    int blob_mode = 1;             /* container floor sizing mode: 1 (per-region, default) | 2 (per-container) */
    std::int64_t chunk_size = 0;   /* 0 = profile default */
    int barrier_fill = 0;          /* 0 = profile default */
    std::string drbg;              /* DRBG fill primitive; "" = profile default (auto tier) */
    int gomaxprocs = 0;            /* 0 = inherit from the environment */
    std::int64_t rekey_every = 0;  /* per-worker iterations between rotations; 0 = never */
    std::int64_t blob_cycle_every = 0; /* per-worker iterations between reopens; 0 = never */
    PayloadMode payload_mode = PayloadMode::Fixed;
    std::uint64_t seed = 0;        /* 0 = OS CSPRNG plaintexts */
    bool json_output = false;
    std::string memprofile;        /* empty = none */
};

/* ------------------------------------------------------------------ */
/* Worker and run state                                                */
/* ------------------------------------------------------------------ */

struct RunState;

/* One worker's private state: its plaintext, its reusable output
 * buffers, its generator, its counters, and the error it stopped on. */
struct Worker {
    int id = 0;
    RunState *run = nullptr;
    std::thread thread;

    std::vector<std::uint8_t> plaintext;
    PayloadMode payload_mode = PayloadMode::Fixed;
    bool seeded = false;
    std::uint64_t rng = 0;          /* splitmix64 state when seeded */

    /* C++-specific. Output accumulators reused across iterations so the
     * steady-state allocation profile of the pump loop stays flat; the
     * message and one-shot entries return their own vectors. */
    std::vector<std::uint8_t> wire;   /* pump-loop wire accumulator */
    std::vector<std::uint8_t> plain;  /* pump-loop round-trip accumulator */
    std::vector<std::uint8_t> scratch; /* pump-loop drain slice */

    /* Counters read by the summary after every worker has returned. */
    std::atomic<std::int64_t> iters{0};
    std::atomic<std::int64_t> bytes_enc{0};
    std::atomic<std::int64_t> bytes_dec{0};
    std::atomic<std::int64_t> nanos_enc{0};
    std::atomic<std::int64_t> nanos_dec{0};

    bool failed = false;
    std::string error;
};

/* The state every worker shares: the Pipeline handles, the retained
 * blobs, the lock that keeps iterations clear of handle mutation, the
 * stop request, the barriers, and the baselines the summary reads. */
struct RunState {
    Config cfg;

    std::optional<itb::Pipeline> stream_pipe;  /* unset unless the shape uses it */
    std::optional<itb::Pipeline> msg_pipe;     /* unset unless the shape uses it */
    std::string stream_profile;
    std::string msg_profile;

    /* Handle mutation. Iterations hold the read side for their whole
     * encrypt -> decrypt -> compare; rekey and blob reopen take the
     * write side, so no cipher call is in flight while a handle's
     * keying changes or the handle itself is swapped, and no encrypt
     * is separated from its decrypt by either. */
    std::shared_mutex pipe_lock;

    /* The blob Init handed out, replaced by every rekey; the input of
     * the next blob reopen. Guarded by pipe_lock. */
    std::vector<std::uint8_t> stream_blob;
    std::vector<std::uint8_t> msg_blob;

    std::atomic<std::int64_t> rekeys{0};
    std::atomic<std::int64_t> blob_cycles{0};

    std::vector<Worker> workers;

    /* Warmup barrier: workers arrive at warmup_done after iteration
     * 0 and at release once main has taken the baselines. */
    std::unique_ptr<std::barrier<>> warmup_done;
    std::unique_ptr<std::barrier<>> release;

    /* Set by the duration deadline, by a signal, or by a failing
     * worker; checked by every worker before it starts an iteration. */
    std::atomic<bool> stop{false};

    /* Main waits on done_cv for active to reach zero; the last
     * returning worker stamps finish_ns so elapsed excludes the
     * wake-up latency of the waiter. */
    std::mutex done_mu;
    std::condition_variable done_cv;
    int active = 0;
    std::int64_t start_ns = 0;
    std::int64_t finish_ns = 0;

    /* Baselines taken after the warmup barrier and at shutdown. */
    std::uint64_t rss_warmup = 0;
    std::uint64_t rss_peak = 0;
    std::uint64_t rss_final = 0;
    std::vector<std::int64_t> pool_warmup;
    std::vector<std::int64_t> pool_steady;
};

/* ------------------------------------------------------------------ */
/* size unit                                                           */
/* ------------------------------------------------------------------ */

bool parse_size(std::string_view s, std::int64_t &out);
bool parse_duration(std::string_view s, std::int64_t &out_ns);
std::int64_t now_ns();
std::string human_bytes(std::int64_t n);
std::string human_bytes_signed(std::int64_t n);
std::string human_rate(std::int64_t bytes, std::int64_t ns);
std::string human_duration(std::int64_t ns);
double mb_per_sec(std::int64_t bytes, std::int64_t ns);

/* ------------------------------------------------------------------ */
/* payload unit                                                        */
/* ------------------------------------------------------------------ */

const char *payload_mode_name(PayloadMode mode);
bool parse_payload_mode(std::string_view s, PayloadMode &out);
std::uint64_t seed_worker(std::uint64_t seed, int worker_id);
bool fill_payload(PayloadMode mode, bool seeded, std::uint64_t &rng,
                  std::span<std::uint8_t> buf);
bool fill_random(std::span<std::uint8_t> buf);

/* ------------------------------------------------------------------ */
/* ops unit                                                            */
/* ------------------------------------------------------------------ */

bool worker_maintenance(Worker &w, std::int64_t iter);

/* ------------------------------------------------------------------ */
/* worker unit                                                         */
/* ------------------------------------------------------------------ */

const char *shape_name(Shape shape);
bool parse_shape(std::string_view s, Shape &out);
void worker_main(Worker *w);
void worker_fail(Worker &w, std::string text);

/* ------------------------------------------------------------------ */
/* summary unit                                                        */
/* ------------------------------------------------------------------ */

void read_rss(std::uint64_t &current, std::uint64_t &peak);
bool pool_snapshot_alloc(std::vector<std::int64_t> &dst);
bool pool_snapshot_take(std::vector<std::int64_t> &dst);
int final_summary(RunState &r, std::int64_t elapsed_ns);

/* ------------------------------------------------------------------ */
/* main unit                                                           */
/* ------------------------------------------------------------------ */

/* C++-specific. printf-style composition into a std::string, so a log
 * line is built whole before it reaches the stream and every format
 * string is checked by the compiler. */
[[gnu::format(printf, 1, 2)]] std::string fmt(const char *f, ...);

void log_line(const std::string &text);
void err_line(const std::string &text);
const char *on_off(bool b);
std::string policy_label(const char *env);

/* Renders a failed library call the way every implementation reports
 * one: the numeric status the binding's own surface carries, then the
 * sentence the library left behind. */
std::string detail(const itb::Error &e);

} // namespace loop

#endif /* ITB_LOOP_HPP */
