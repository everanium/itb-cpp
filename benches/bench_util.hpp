/*
 * bench_util.hpp — shared timing + reporting helpers for the C++
 * binding micro-benchmarks. Wall-clock via
 * clock_gettime(CLOCK_MONOTONIC); output is a fixed-width table:
 *
 *   bench             size     mb_per_sec
 *   message           1 MiB    <n>
 *   ...
 */

#ifndef ITB_BENCH_UTIL_HPP
#define ITB_BENCH_UTIL_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include <sys/random.h>

#include "itb.hpp"

/* Per-case wall-clock budget (seconds, env: ITB_BENCH_MIN_SEC)
 * and iteration floor. */
inline constexpr std::size_t kBenchMinIters = 3;

inline double bench_min_seconds()
{
    const char *raw = std::getenv("ITB_BENCH_MIN_SEC");
    if (raw != nullptr && *raw != '\0') {
        double v = std::strtod(raw, nullptr);
        if (v > 0.0) {
            return v;
        }
    }
    return 5.0;
}

/* Reads the bench-shape env vars and builds an itb::Opts. Defaults
 * match root Go BENCH3.md so numbers are directly comparable. */
inline itb::Opts bench_build_opts()
{
    const auto env_or = [](const char *name, const char *fallback) {
        const char *v = std::getenv(name);
        return (v != nullptr && *v != '\0') ? v : fallback;
    };
    const auto env_bool = [](const char *name) {
        const char *v = std::getenv(name);
        return (v != nullptr &&
                (std::strcmp(v, "true") == 0 || std::strcmp(v, "1") == 0))
                   ? "true"
                   : "false";
    };
    itb::Opts opts;
    opts.set("nonceBits", env_or("ITB_NONCE_BITS", "512"))
        .set("keyBits", env_or("ITB_KEY_BITS", "1024"))
        .set("withParallax", env_bool("ITB_WITH_PARALLAX"))
        .set("withWrapper", env_bool("ITB_WITH_WRAPPER"))
        .set("innerHash", env_or("ITB_INNER_HASH", "areion512"));
    const char *mac_name = std::getenv("ITB_MAC_NAME");
    if (mac_name != nullptr && *mac_name != '\0') {
        opts.set("macName", mac_name);
    }
    return opts;
}

inline const char *bench_profile_name(const char *fallback)
{
    const char *env = std::getenv("ITB_PROFILE");
    return (env != nullptr && *env != '\0') ? env : fallback;
}

inline double bench_now()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) +
           static_cast<double>(ts.tv_nsec) / 1e9;
}

inline void bench_header()
{
    std::printf("%-17s %-8s %s\n", "bench", "size", "mb_per_sec");
}

inline std::string bench_size_label(std::size_t size)
{
    if (size >= (std::size_t{1} << 20)) {
        return std::to_string(size >> 20) + " MiB";
    }
    return std::to_string(size >> 10) + " KiB";
}

/* CSPRNG-fill so plaintext content matches the root Go bench
 * (crypto/rand). getrandom returns at most ~33 MiB per call on
 * Linux, so loop until the whole buffer is filled. Never called
 * inside a timing loop. */
inline void bench_csprng_fill(std::vector<std::uint8_t> &buf)
{
    for (std::size_t off = 0; off < buf.size();) {
        ssize_t r = getrandom(buf.data() + off, buf.size() - off, 0);
        if (r <= 0) {
            std::fprintf(stderr, "bench: getrandom failed\n");
            std::exit(1);
        }
        off += static_cast<std::size_t>(r);
    }
}

/* Runs fn until the wall-clock budget is spent (with an iteration
 * floor + one untimed warm-up), then prints one table row. fn throws
 * on failure; the caller's top-level catch aborts the process. */
template <typename Fn>
inline void bench_case(const char *name, std::size_t size, Fn &&fn)
{
    fn(); /* warm-up */
    const double start = bench_now();
    double elapsed = 0.0;
    std::size_t iters = 0;
    const double budget = bench_min_seconds();
    while (elapsed < budget || iters < kBenchMinIters) {
        fn();
        iters++;
        elapsed = bench_now() - start;
    }
    const double mb = static_cast<double>(size) * static_cast<double>(iters) /
                      (1024.0 * 1024.0);
    std::printf("%-17s %-8s %.1f\n", name, bench_size_label(size).c_str(),
                mb / elapsed);
}

#endif /* ITB_BENCH_UTIL_HPP */
