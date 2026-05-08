// common.hpp — shared scaffolding for the C++ binding's Easy Mode
// bench binaries.
//
// The harness mirrors the Go `testing.B` benchmark style on the
// itb_ext_test.go / itb3_ext_test.go side: each bench function runs a
// short warm-up batch to reach steady state, then a measured batch
// whose total wall-clock time is divided by the iteration count to
// produce the canonical `ns/op` throughput line. The output line also
// carries an MB/s figure derived from the configured payload size.
//
// Header-only by construction. The C++ Makefile compiles every
// bench/bench_*.cpp standalone — there is no shared common.cpp
// translation unit — so every helper here is `inline`.
//
// Environment variables (mirrored from itb's bitbyte_test.go +
// extended for Easy Mode):
//
//   ITB_NONCE_BITS    process-wide nonce width override; valid values
//                     128 / 256 / 512. Maps to itb::set_nonce_bits
//                     before any encryptor is constructed. Default 128.
//   ITB_LOCKSEED      when set to a non-empty / non-`0` value, every
//                     Easy Mode encryptor in this run calls
//                     enc.set_lock_seed(1). The Go side's auto-couple
//                     invariant then engages BitSoup + LockSoup
//                     automatically. Default off.
//   ITB_BENCH_FILTER  substring filter on bench-case names; only cases
//                     whose name contains the filter run. Default unset.
//   ITB_BENCH_MIN_SEC minimum measured wall-clock seconds per case.
//                     Default 5.0 — wide enough to absorb the
//                     cold-cache / warm-up transient that distorts
//                     shorter measurement windows on the 16 MiB
//                     encrypt / decrypt path.
//
// Worker count defaults to itb::set_max_workers(0) (auto-detect),
// matching the Go bench default.

#pragma once

#include <itb.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace bench {

// Default 16 MiB CSPRNG-filled payload, matching the Go bench / Python
// bench / Rust bench / D bench surfaces.
inline constexpr std::size_t kPayload16MB = static_cast<std::size_t>(16) << 20;

// Canonical PRF-grade primitive order. Mirrored verbatim across every
// binding's bench harness so cross-language diff comparisons align
// row-for-row. Per CLAUDE.md "binding-side canonical order" exception
// under "Primitive ordering ...". The three below-spec lab primitives
// (CRC128, FNV-1a, MD5) are not exposed through the libitb registry
// and are absent here by construction.
inline constexpr const char* kPrimitivesCanonical[] = {
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
};
inline constexpr std::size_t kPrimitivesCanonicalLen =
    sizeof(kPrimitivesCanonical) / sizeof(kPrimitivesCanonical[0]);

// ----- Env-var probes ------------------------------------------------

inline int env_nonce_bits(int default_value) {
    const char* v = std::getenv("ITB_NONCE_BITS");
    if (v == nullptr || v[0] == '\0') {
        return default_value;
    }
    if (std::strcmp(v, "128") == 0) return 128;
    if (std::strcmp(v, "256") == 0) return 256;
    if (std::strcmp(v, "512") == 0) return 512;
    std::fprintf(stderr,
                 "ITB_NONCE_BITS=%s invalid (expected 128/256/512); using %d\n",
                 v, default_value);
    return default_value;
}

inline bool env_lock_seed() {
    const char* v = std::getenv("ITB_LOCKSEED");
    if (v == nullptr || v[0] == '\0') {
        return false;
    }
    if (std::strcmp(v, "0") == 0) {
        return false;
    }
    return true;
}

inline const char* env_filter() {
    const char* v = std::getenv("ITB_BENCH_FILTER");
    if (v == nullptr || v[0] == '\0') {
        return nullptr;
    }
    return v;
}

inline double env_min_seconds() {
    const char* v = std::getenv("ITB_BENCH_MIN_SEC");
    if (v == nullptr || v[0] == '\0') {
        return 5.0;
    }
    char* endp = nullptr;
    double f = std::strtod(v, &endp);
    if (endp == v || (endp != nullptr && *endp != '\0') || f <= 0.0) {
        std::fprintf(stderr,
                     "ITB_BENCH_MIN_SEC=%s invalid (expected positive float); using 5.0\n",
                     v);
        return 5.0;
    }
    return f;
}

// ----- xorshift64* random fill --------------------------------------

// Per-process counter so successive random_bytes calls within the same
// nanosecond still diverge. Not thread-safe; the bench harness is
// single-threaded by design (libitb's worker pool absorbs whatever
// parallelism the case body exposes).
inline std::uint64_t& random_counter_ref() {
    static std::uint64_t counter = 0;
    return counter;
}

inline std::uint64_t monotonic_nanos() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

// Fills `out` with `len` non-deterministic test bytes via a clock-seeded
// xorshift64* LCG. The bench harness does not require cryptographic
// strength here, only that the payload is non-uniform and changes
// between runs so a primitive cannot collapse on a constant input.
inline void random_bytes(std::uint8_t* out, std::size_t len) {
    if (out == nullptr || len == 0) {
        return;
    }
    random_counter_ref() += 1;
    std::uint64_t state = (monotonic_nanos() * 0x9E3779B97F4A7C15ULL)
                          + random_counter_ref()
                          + 0xBF58476D1CE4E5B9ULL;
    if (state == 0) {
        state = 0xDEADBEEFCAFEF00DULL;
    }
    std::size_t i = 0;
    while (i < len) {
        // xorshift64* — adequate for non-cryptographic test fill.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        std::uint64_t v = state * 0x2545F4914F6CDD1DULL;
        std::size_t take = (len - i) < 8 ? (len - i) : 8;
        for (std::size_t k = 0; k < take; k++) {
            out[i + k] = static_cast<std::uint8_t>((v >> (8 * k)) & 0xFFu);
        }
        i += take;
    }
}

inline std::vector<std::uint8_t> random_bytes_vec(std::size_t len) {
    std::vector<std::uint8_t> v(len);
    random_bytes(v.data(), v.size());
    return v;
}

// ----- Bench-case definition ---------------------------------------

// Per-iter callable; accepts an iteration count and runs the per-iter
// body that many times. The harness measures wall-clock time outside
// the callable.
using BenchFn = std::function<void(std::uint64_t)>;

// One bench case: name + per-iter callable + payload byte count (used
// to compute the MB/s column).
struct BenchCase {
    std::string name;
    BenchFn run;
    std::size_t payload_bytes = 0;
};

// ----- Substring containment ---------------------------------------

inline bool contains(const std::string& haystack, const char* needle) {
    if (needle == nullptr || needle[0] == '\0') {
        return true;
    }
    return haystack.find(needle) != std::string::npos;
}

// ----- Single-case measurement -------------------------------------

// Convergence policy mirrors common.c / common.d / common.rs / common.py:
//
//   1) Warm-up — one iteration to hit cache / cold-start transients
//      before the measured loop.
//   2) Measurement — keep doubling the iteration count until the
//      measured wall-clock duration meets min_seconds. Iteration count
//      is capped at 1 << 24 so a very fast op cannot escalate past
//      that ceiling for one batch.
//   3) Report — final batch's total ns / iters → ns/op; payload_bytes
//      / ns_per_op → MB/s.
inline void measure(BenchCase& c, double min_seconds) {
    // Warm-up — one iteration.
    c.run(1);

    std::int64_t min_ns = static_cast<std::int64_t>(min_seconds * 1.0e9);
    std::uint64_t iters = 1;
    std::int64_t elapsed_ns = 0;

    for (;;) {
        auto t0 = std::chrono::steady_clock::now();
        c.run(iters);
        auto t1 = std::chrono::steady_clock::now();
        elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         t1 - t0)
                         .count();
        if (elapsed_ns >= min_ns) {
            break;
        }
        if (iters >= (static_cast<std::uint64_t>(1) << 24)) {
            break;
        }
        iters *= 2u;
    }

    double ns_per_op = static_cast<double>(elapsed_ns)
                       / static_cast<double>(iters);
    double mb_per_s = 0.0;
    if (ns_per_op > 0.0) {
        double bytes_per_sec = static_cast<double>(c.payload_bytes)
                               / (ns_per_op / 1.0e9);
        mb_per_s = bytes_per_sec / static_cast<double>(1u << 20);
    }
    // Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
    // column-aligned for human reading.
    std::printf("%-60s\t%10llu\t%14.1f ns/op\t%9.2f MB/s\n",
                c.name.c_str(),
                static_cast<unsigned long long>(iters),
                ns_per_op,
                mb_per_s);
    std::fflush(stdout);
}

// ----- Public driver -----------------------------------------------

// Run every case in `cases` and print one Go-bench-style line per case
// to stdout. Honours ITB_BENCH_FILTER for substring scoping and
// ITB_BENCH_MIN_SEC for per-case wall-clock budget.
inline void run_all(std::vector<BenchCase>& cases) {
    const char* flt = env_filter();
    double min_seconds = env_min_seconds();

    std::size_t selected = 0;
    for (auto& c : cases) {
        if (flt == nullptr || contains(c.name, flt)) {
            selected++;
        }
    }

    if (selected == 0) {
        std::fprintf(stderr,
                     "no bench cases match filter %s; available:",
                     flt == nullptr ? "<unset>" : flt);
        for (auto& c : cases) {
            std::fprintf(stderr, " %s", c.name.c_str());
        }
        std::fprintf(stderr, "\n");
        return;
    }

    std::size_t payload_bytes = 0;
    for (auto& c : cases) {
        if (flt == nullptr || contains(c.name, flt)) {
            payload_bytes = c.payload_bytes;
            break;
        }
    }
    std::printf("# benchmarks=%zu payload_bytes=%zu min_seconds=%g\n",
                selected, payload_bytes, min_seconds);
    std::fflush(stdout);

    for (auto& c : cases) {
        if (flt == nullptr || contains(c.name, flt)) {
            measure(c, min_seconds);
        }
    }
}

} // namespace bench
