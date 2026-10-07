/* The runtime surface the stress harness drives: GOMAXPROCS, the heap
 * profile, the pool counters, the shipped hash-registry enumeration,
 * and the auto DRBG tier report. */

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "test_util.hpp"

static int run()
{
    /* GOMAXPROCS: zero queries, a positive value sets and returns the
     * previous one. The original value is restored so a later test in
     * the same binary is unaffected. */
    const int original = itb::set_gomaxprocs(0);
    TEST_ASSERT(original > 0, "query must report a positive GOMAXPROCS, got %d", original);
    const int previous = itb::set_gomaxprocs(2);
    TEST_ASSERT(previous == original, "set must return the previous value, %d != %d",
                previous, original);
    TEST_ASSERT(itb::set_gomaxprocs(0) == 2, "GOMAXPROCS must read back as 2");
    (void)itb::set_gomaxprocs(original);

    /* Pool counters: the slot count comes from the library, the layout
     * is 1 + 5*T + 8 with T in slot 0, and every counter is a
     * non-negative monotonic total. */
    const std::size_t slots = itb::pool_stats_len();
    TEST_ASSERT(slots >= 9, "pool_stats_len must report at least 9 slots, got %zu", slots);
    std::vector<std::int64_t> counters(slots);
    const std::size_t written = itb::pool_stats(counters);
    TEST_ASSERT(written == slots, "pool_stats wrote %zu of %zu slots", written, slots);
    const std::int64_t tiers = counters[0];
    TEST_ASSERT(tiers > 0, "slot 0 must carry the tier count, got %lld",
                static_cast<long long>(tiers));
    TEST_ASSERT(static_cast<std::size_t>(1 + 5 * tiers + 8) == slots,
                "layout 1 + 5*%lld + 8 != %zu", static_cast<long long>(tiers), slots);
    for (std::size_t i = 0; i < slots; i++) {
        TEST_ASSERT(counters[i] >= 0, "counter %zu is negative", i);
    }

    /* A destination shorter than the requirement is a relayed
     * BufferTooSmall, not a silent truncation. */
    bool too_small = false;
    try {
        std::vector<std::int64_t> narrow(1);
        (void)itb::pool_stats(narrow);
    } catch (const itb::Error &e) {
        too_small = e.status() == itb::Status::BufferTooSmall;
    }
    TEST_ASSERT(too_small, "a short destination must raise BufferTooSmall");

    /* Heap profile: a writable path yields a non-empty pprof file
     * whose gzip magic is intact; an unwritable one throws. */
    const std::string path = std::string("/tmp/itb-cpp-runtime-test-") +
                             std::to_string(static_cast<long long>(itb::pool_stats_len())) +
                             ".pprof";
    itb::write_heap_profile(path);
    std::FILE *f = std::fopen(path.c_str(), "rb");
    TEST_ASSERT(f != nullptr, "heap profile was not created at %s", path.c_str());
    unsigned char magic[2] = {0, 0};
    const std::size_t got = std::fread(magic, 1, sizeof(magic), f);
    std::fclose(f);
    std::remove(path.c_str());
    TEST_ASSERT(got == 2 && magic[0] == 0x1f && magic[1] == 0x8b,
                "heap profile is not a gzip stream");

    bool rejected = false;
    try {
        itb::write_heap_profile("/proc/itb-no-such-directory/heap.pprof");
    } catch (const itb::Error &) {
        rejected = true;
    }
    TEST_ASSERT(rejected, "an unwritable path must throw");

    /* Hash registry: a JSON array of strings carrying the names
     * Pipeline::init accepts, with the canonical first entry present. */
    const std::string names = itb::hash_names();
    TEST_ASSERT(names.size() > 2 && names.front() == '[' && names.back() == ']',
                "hash_names must be a JSON array, got %s", names.c_str());
    TEST_ASSERT(names.find("\"areion512\"") != std::string::npos,
                "hash_names must carry areion512");
    TEST_ASSERT(names.find("\"aesitb128\"") != std::string::npos,
                "hash_names must carry aesitb128");
    TEST_ASSERT(names.find("\"nope\"") == std::string::npos,
                "hash_names must not carry an unregistered name");

    /* The enumeration is the authority the flag validation reads: a
     * name it carries constructs, one it does not is rejected. */
    itb::Opts opts;
    opts.set("innerHash", "blake3");
    itb::Pipeline p = itb::Pipeline::init("singlemsg-triple-mac-v1", opts);
    TEST_ASSERT(!p.save().empty(), "a registry name must construct");

    /* Auto DRBG tier: one of the two fill ciphers, resolved per host. */
    const std::string tier = itb::drbg_auto_tier();
    TEST_ASSERT(tier == "aes-256-ctr" || tier == "chacha20", "drbg auto tier: %s", tier.c_str());
    return 0;
}

TEST_MAIN(run)
