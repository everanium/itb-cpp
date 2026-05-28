// test_config.cpp — process-global configuration round-trip tests.
//
// Mirrors bindings/c/tests/test_config.c. Mutates libitb's
// process-wide atomics (bit_soup, lock_soup, max_workers, nonce_bits,
// barrier_fill); per-binary process isolation gives this test its own
// libitb global state, so no in-process serial lock is required.
//
// Each TEST_CASE that touches a setter constructs a small RAII guard
// inside the body so the original value is restored on exit even if a
// REQUIRE / FAIL aborts mid-body. A file-scope guard would be wrong:
// catch2 runs every TEST_CASE in the same process, so a global guard
// would only restore at program-shutdown.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstddef>

namespace {

// Per-setter RAII guard. The save / restore ordering is deliberate:
// every setter is read once at construction and re-applied verbatim
// at destruction. The destructor is best-effort — propagating
// exceptions from a destructor would terminate the program.
class BitSoupGuard {
public:
    BitSoupGuard() : saved_{itb::get_bit_soup()} {}
    ~BitSoupGuard() {
        try { itb::set_bit_soup(saved_); } catch (...) {}
    }
    BitSoupGuard(const BitSoupGuard&)            = delete;
    BitSoupGuard& operator=(const BitSoupGuard&) = delete;
private:
    int saved_;
};

class LockSoupGuard {
public:
    LockSoupGuard() : saved_{itb::get_lock_soup()} {}
    ~LockSoupGuard() {
        try { itb::set_lock_soup(saved_); } catch (...) {}
    }
    LockSoupGuard(const LockSoupGuard&)            = delete;
    LockSoupGuard& operator=(const LockSoupGuard&) = delete;
private:
    int saved_;
};

class LockBatchGuard {
public:
    LockBatchGuard() : saved_{itb::get_lock_batch()} {}
    ~LockBatchGuard() {
        try { itb::set_lock_batch(saved_); } catch (...) {}
    }
    LockBatchGuard(const LockBatchGuard&)            = delete;
    LockBatchGuard& operator=(const LockBatchGuard&) = delete;
private:
    int saved_;
};

class MaxWorkersGuard {
public:
    MaxWorkersGuard() : saved_{itb::get_max_workers()} {}
    ~MaxWorkersGuard() {
        try { itb::set_max_workers(saved_); } catch (...) {}
    }
    MaxWorkersGuard(const MaxWorkersGuard&)            = delete;
    MaxWorkersGuard& operator=(const MaxWorkersGuard&) = delete;
private:
    int saved_;
};

class NonceBitsGuard {
public:
    NonceBitsGuard() : saved_{itb::get_nonce_bits()} {}
    ~NonceBitsGuard() {
        try { itb::set_nonce_bits(saved_); } catch (...) {}
    }
    NonceBitsGuard(const NonceBitsGuard&)            = delete;
    NonceBitsGuard& operator=(const NonceBitsGuard&) = delete;
private:
    int saved_;
};

class BarrierFillGuard {
public:
    BarrierFillGuard() : saved_{itb::get_barrier_fill()} {}
    ~BarrierFillGuard() {
        try { itb::set_barrier_fill(saved_); } catch (...) {}
    }
    BarrierFillGuard(const BarrierFillGuard&)            = delete;
    BarrierFillGuard& operator=(const BarrierFillGuard&) = delete;
private:
    int saved_;
};

} // namespace

TEST_CASE("config bit_soup round-trip", "[config][bit_soup]") {
    BitSoupGuard guard;
    itb::set_bit_soup(1);
    REQUIRE(itb::get_bit_soup() == 1);
    itb::set_bit_soup(0);
    REQUIRE(itb::get_bit_soup() == 0);
}

TEST_CASE("config lock_soup round-trip", "[config][lock_soup]") {
    // lock_soup auto-couples bit_soup; restore both.
    BitSoupGuard  bs_guard;
    LockSoupGuard ls_guard;
    itb::set_lock_soup(1);
    REQUIRE(itb::get_lock_soup() == 1);
    // lock_soup=1 forces bit_soup=1 inside libitb.
    REQUIRE(itb::get_bit_soup() == 1);
}

TEST_CASE("config lock_batch round-trip", "[config][lock_batch]") {
    LockBatchGuard guard;
    itb::set_lock_batch(1);
    REQUIRE(itb::get_lock_batch() == 1);
}

TEST_CASE("config max_workers round-trip", "[config][max_workers]") {
    MaxWorkersGuard guard;
    itb::set_max_workers(4);
    REQUIRE(itb::get_max_workers() == 4);
    itb::set_max_workers(1);
    REQUIRE(itb::get_max_workers() == 1);
}

TEST_CASE("config nonce_bits accepts only 128 / 256 / 512",
          "[config][nonce_bits][valid]") {
    NonceBitsGuard guard;
    static const int kValid[] = {128, 256, 512};
    for (int v : kValid) {
        itb::set_nonce_bits(v);
        REQUIRE(itb::get_nonce_bits() == v);
    }
}

TEST_CASE("config nonce_bits rejects invalid values",
          "[config][nonce_bits][invalid]") {
    NonceBitsGuard guard;
    static const int kBad[] = {0, 1, 64, 192, 1024};
    for (int v : kBad) {
        try {
            itb::set_nonce_bits(v);
            FAIL("expected ItbError(BAD_INPUT) for nonce_bits=" + std::to_string(v));
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBadInput);
        }
    }
}

TEST_CASE("config barrier_fill accepts only powers-of-two up to 32",
          "[config][barrier_fill][valid]") {
    BarrierFillGuard guard;
    static const int kValid[] = {1, 2, 4, 8, 16, 32};
    for (int v : kValid) {
        itb::set_barrier_fill(v);
        REQUIRE(itb::get_barrier_fill() == v);
    }
}

TEST_CASE("config barrier_fill rejects unsupported values",
          "[config][barrier_fill][invalid]") {
    BarrierFillGuard guard;
    static const int kBad[] = {0, 3, 5, 7, 64};
    for (int v : kBad) {
        try {
            itb::set_barrier_fill(v);
            FAIL("expected ItbError(BAD_INPUT) for barrier_fill="
                 + std::to_string(v));
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBadInput);
        }
    }
}
