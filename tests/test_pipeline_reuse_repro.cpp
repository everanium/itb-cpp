/* Pipeline-reuse reproducer: one Pipeline, a bench-shaped timed loop
 * of encrypt_stream_pump_into calls at 1 MiB into a shared pre-sized
 * dst (itb::out_bound), followed by one allocating
 * encrypt_stream_pump and one 16 MiB pump_into on the same Pipeline.
 *
 * Probes the reported failure where the pump on a reused Pipeline
 * throws "stream pump dst too small" (or Stream::write status 99)
 * after a timed loop completes. Per-iteration produced sizes are
 * tracked so any monotonic wire-size growth past the bound is visible
 * in the failure report.
 *
 * Env knobs:
 *   ITB_REPRO_SECONDS  wall-clock budget for the timed loop (default 6)
 *   ITB_REPRO_PROFILE  profile name (default streaming-noaead-triple-v1)
 */

#include <cstdlib>
#include <cstring>
#include <ctime>

#include "test_util.hpp"

static double repro_now()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) +
           static_cast<double>(ts.tv_nsec) / 1e9;
}

static int run()
{
    /* Mirror the bench's runtime shape so the repro sees the same
     * GC pressure the bench does. */
    (void)itb::set_memory_limit(512LL << 20);
    (void)itb::set_gc_percent(20);

    const char *profile_env = std::getenv("ITB_REPRO_PROFILE");
    const char *profile = (profile_env != nullptr && *profile_env != '\0')
                              ? profile_env
                              : "streaming-noaead-triple-v1";
    double seconds = 6.0;
    if (const char *raw = std::getenv("ITB_REPRO_SECONDS");
        raw != nullptr && *raw != '\0') {
        double v = std::strtod(raw, nullptr);
        if (v > 0.0) {
            seconds = v;
        }
    }

    /* Bench-shape opts (canonical bench config + env overrides). */
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

    itb::Pipeline pipe = itb::Pipeline::init(profile, opts);

    const std::size_t size = std::size_t{1} << 20;
    const std::vector<std::uint8_t> plain = test_payload(size, 0x9E3779B9u);
    std::vector<std::uint8_t> wire(itb::out_bound(size));

    std::size_t iters = 0;
    std::size_t min_n = SIZE_MAX;
    std::size_t max_n = 0;
    const double start = repro_now();
    for (;;) {
        std::size_t n = 0;
        try {
            n = pipe.encrypt_stream_pump_into(itb::as_bytes(plain),
                                              itb::as_writable_bytes(wire));
        } catch (const std::exception &e) {
            std::fprintf(stderr,
                         "repro: pump_into FAILED at iter %zu "
                         "(min_n=%zu max_n=%zu dst=%zu): %s\n",
                         iters, min_n, max_n, wire.size(), e.what());
            return 1;
        }
        if (n < min_n) {
            min_n = n;
        }
        if (n > max_n) {
            max_n = n;
        }
        iters++;
        if (repro_now() - start >= seconds && iters >= 3) {
            break;
        }
    }
    std::fprintf(stderr,
                 "repro: timed loop OK — %zu iters, produced "
                 "min=%zu max=%zu, dst=%zu\n",
                 iters, min_n, max_n, wire.size());

    /* The reported failure point: one more pump on the same Pipeline
     * right after the timed loop completes. */
    std::vector<std::uint8_t> out;
    try {
        out = pipe.encrypt_stream_pump(itb::as_bytes(plain));
    } catch (const std::exception &e) {
        std::fprintf(stderr, "repro: post-loop encrypt_stream_pump FAILED: %s\n",
                     e.what());
        return 1;
    }
    TEST_ASSERT(!out.empty(), "post-loop pump produced empty wire");
    std::fprintf(stderr, "repro: post-loop pump OK — %zu bytes\n", out.size());

    /* Second size on the same Pipeline (the production-shape report
     * failed right after the first size case). */
    const std::size_t size16 = std::size_t{16} << 20;
    const std::vector<std::uint8_t> plain16 = test_payload(size16, 0xC2B2AE35u);
    std::vector<std::uint8_t> wire16(itb::out_bound(size16));
    try {
        const std::size_t n16 = pipe.encrypt_stream_pump_into(
            itb::as_bytes(plain16), itb::as_writable_bytes(wire16));
        std::fprintf(stderr, "repro: 16 MiB pump_into OK — %zu bytes (dst=%zu)\n",
                     n16, wire16.size());
    } catch (const std::exception &e) {
        std::fprintf(stderr, "repro: 16 MiB pump_into FAILED: %s\n", e.what());
        return 1;
    }

    /* Decrypt stress with an EXACTLY-sized dst (the bench decrypt
     * loop's shape: dec_out is precisely the plaintext length). The
     * finished flag on the Go side can lag the final produced byte
     * by one teardown window; a drain loop that treats "dst full"
     * as an error before probing for the flag throws spuriously
     * here. Loop enough times to give the race window a chance. */
    std::vector<std::uint8_t> dec_out(size);
    std::size_t dec_iters = 0;
    const double dec_start = repro_now();
    for (;;) {
        try {
            const std::size_t dn = pipe.decrypt_stream_pump_into(
                itb::as_bytes(std::span<const std::uint8_t>(out)),
                itb::as_writable_bytes(dec_out));
            TEST_ASSERT(dn == size, "decrypt length %zu != %zu", dn, size);
        } catch (const std::exception &e) {
            std::fprintf(stderr,
                         "repro: exact-dst decrypt FAILED at iter %zu: %s\n",
                         dec_iters, e.what());
            return 1;
        }
        dec_iters++;
        if (repro_now() - dec_start >= seconds && dec_iters >= 3) {
            break;
        }
    }
    TEST_ASSERT(std::memcmp(dec_out.data(), plain.data(), size) == 0,
                "decrypt payload mismatch");
    std::fprintf(stderr, "repro: exact-dst decrypt OK — %zu iters\n",
                 dec_iters);
    return 0;
}

TEST_MAIN(run)
