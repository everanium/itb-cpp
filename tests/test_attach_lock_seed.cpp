// test_attach_lock_seed.cpp — coverage for the low-level
// `Seed::attach_lock_seed` mutator.
//
// Mirrors bindings/c/tests/test_attach_lock_seed.c on the C++ surface.
//
// The dedicated lockSeed routes the bit-permutation derivation through
// its own state instead of the noiseSeed: the per-chunk PRF closure
// captures both the lockSeed's components AND its hash function, so
// the lockSeed primitive may legitimately differ from the noiseSeed
// primitive within the same native hash width — keying-material
// isolation plus algorithm diversity for defence-in-depth on the
// bit-permutation channel, without changing the public encrypt /
// decrypt signatures.
//
// The bit-permutation overlay must be engaged via `set_bit_soup` or
// `set_lock_soup` before any encrypt call — without the overlay, the
// dedicated lockSeed has no observable effect on the wire output, and
// the libitb build-PRF guard surfaces an `ItbError`. These tests
// exercise both the round-trip path with overlay engaged and the
// attach-time misuse rejections (self-attach, post-encrypt switching,
// width mismatch).
//
// This binary mutates the process-wide `bit_soup` and `lock_soup`
// atomics. An anonymous-namespace RAII guard saves and restores the
// original values around each TEST_CASE, so per-binary process
// isolation is sufficient — no cross-case leak is possible even if a
// REQUIRE / FAIL aborts mid-body.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <vector>

namespace {

// Saves and restores the active process-wide `bit_soup` + `lock_soup`
// values. Restoration is best-effort and intentionally swallows
// destructor-path exceptions — propagating them would terminate the
// program because Catch2 may already be inside an exception unwind.
class SoupGuard {
public:
    SoupGuard()
        : saved_bit_{itb::get_bit_soup()},
          saved_lock_{itb::get_lock_soup()} {}
    ~SoupGuard() {
        try {
            itb::set_lock_soup(saved_lock_);
            itb::set_bit_soup(saved_bit_);
        } catch (...) {
            // intentionally swallowed
        }
    }
    SoupGuard(const SoupGuard&)            = delete;
    SoupGuard& operator=(const SoupGuard&) = delete;
private:
    int saved_bit_;
    int saved_lock_;
};

} // namespace

TEST_CASE("attach_lock_seed round-trip with bit-soup engaged",
          "[attach_lock_seed][roundtrip]") {
    SoupGuard guard;
    // `set_lock_soup(1)` auto-couples `bit_soup=1` inside libitb.
    itb::set_lock_soup(1);

    static const std::uint8_t plaintext_bytes[] =
        "attach_lock_seed roundtrip payload";
    std::vector<std::uint8_t> plaintext(
        plaintext_bytes, plaintext_bytes + sizeof(plaintext_bytes) - 1);

    itb::Seed n {"blake3", 1024};
    itb::Seed d {"blake3", 1024};
    itb::Seed s {"blake3", 1024};
    itb::Seed ls{"blake3", 1024};
    n.attach_lock_seed(ls);

    auto ct = itb::encrypt(n, d, s, plaintext);
    auto pt = itb::decrypt(n, d, s, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("attach_lock_seed persistence across re-built seeds",
          "[attach_lock_seed][persistence]") {
    SoupGuard guard;
    itb::set_lock_soup(1);

    static const std::uint8_t plaintext_bytes[] =
        "cross-process attach lockseed roundtrip";
    std::vector<std::uint8_t> plaintext(
        plaintext_bytes, plaintext_bytes + sizeof(plaintext_bytes) - 1);

    // Day 1 — sender.
    itb::Seed n {"blake3", 1024};
    itb::Seed d {"blake3", 1024};
    itb::Seed s {"blake3", 1024};
    itb::Seed ls{"blake3", 1024};
    n.attach_lock_seed(ls);

    auto n_comps  = n.components();
    auto d_comps  = d.components();
    auto s_comps  = s.components();
    auto ls_comps = ls.components();
    auto n_key    = n.hash_key();
    auto d_key    = d.hash_key();
    auto s_key    = s.hash_key();
    auto ls_key   = ls.hash_key();

    auto ct = itb::encrypt(n, d, s, plaintext);

    // Day 2 — receiver rebuilds from the saved material.
    itb::Seed n2  = itb::Seed::from_components("blake3", n_comps,  n_key);
    itb::Seed d2  = itb::Seed::from_components("blake3", d_comps,  d_key);
    itb::Seed s2  = itb::Seed::from_components("blake3", s_comps,  s_key);
    itb::Seed ls2 = itb::Seed::from_components("blake3", ls_comps, ls_key);
    n2.attach_lock_seed(ls2);

    auto pt = itb::decrypt(n2, d2, s2, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("attach_lock_seed self-attach is rejected",
          "[attach_lock_seed][self_attach]") {
    // No overlay mutation needed — the rejection happens at attach
    // time, before any encrypt call.
    itb::Seed n{"blake3", 1024};
    try {
        n.attach_lock_seed(n);
        FAIL("expected ItbError(BAD_INPUT) on self-attach");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("attach_lock_seed width mismatch is rejected",
          "[attach_lock_seed][width_mismatch]") {
    itb::Seed n_256{"blake3",    1024}; // width 256
    itb::Seed l_128{"siphash24", 1024}; // width 128
    try {
        n_256.attach_lock_seed(l_128);
        FAIL("expected ItbError(SEED_WIDTH_MIX) on width mismatch");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kSeedWidthMix);
    }
}

TEST_CASE("attach_lock_seed post-encrypt switch is rejected",
          "[attach_lock_seed][post_encrypt]") {
    SoupGuard guard;
    itb::set_lock_soup(1);

    itb::Seed n {"blake3", 1024};
    itb::Seed d {"blake3", 1024};
    itb::Seed s {"blake3", 1024};
    itb::Seed ls{"blake3", 1024};
    n.attach_lock_seed(ls);

    // Encrypt once — locks future attach_lock_seed calls on this
    // noise seed.
    static const std::uint8_t pre[] = "pre-switch";
    std::vector<std::uint8_t> pre_pt(pre, pre + sizeof(pre) - 1);
    auto ct = itb::encrypt(n, d, s, pre_pt);
    REQUIRE(!ct.empty());

    itb::Seed ls2{"blake3", 1024};
    try {
        n.attach_lock_seed(ls2);
        FAIL("expected ItbError(BAD_INPUT) on post-encrypt switch");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("attach_lock_seed encrypt fails when overlay is off",
          "[attach_lock_seed][overlay_off]") {
    SoupGuard guard;
    itb::set_bit_soup(0);
    itb::set_lock_soup(0);

    itb::Seed n {"blake3", 1024};
    itb::Seed d {"blake3", 1024};
    itb::Seed s {"blake3", 1024};
    itb::Seed ls{"blake3", 1024};
    n.attach_lock_seed(ls);

    static const std::uint8_t pt_bytes[] = "overlay off - should fail";
    std::vector<std::uint8_t> plaintext(
        pt_bytes, pt_bytes + sizeof(pt_bytes) - 1);
    REQUIRE_THROWS_AS(itb::encrypt(n, d, s, plaintext), itb::ItbError);
}
