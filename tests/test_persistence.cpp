// test_persistence.cpp — cross-process persistence round-trip tests
// for the low-level Seed::components / Seed::hash_key /
// Seed::from_components surface.
//
// Mirrors bindings/c/tests/test_persistence.c. Exercises the
// persistence path across every primitive in the registry × the three
// ITB key-bit widths (512 / 1024 / 2048) that are valid for each
// native hash width.
//
// Without both `components` and `hash_key` captured at encrypt-side
// and re-supplied at decrypt-side, the seed state cannot be
// reconstructed and the ciphertext is unreadable. SipHash-2-4 has no
// internal fixed key — its keying material is the seed components
// themselves — so its `hash_key()` returns an empty vector and the
// `from_components` rebuild reads through cleanly with `hash_key`
// passed empty.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct CanonicalHash {
    const char* name;
    int width;
};

constexpr CanonicalHash kCanonicalHashes[] = {
    {"areion256",  256},
    {"areion512",  512},
    {"blake2b256", 256},
    {"blake2b512", 512},
    {"blake2s",    256},
    {"blake3",     256},
    {"aescmac",    128},
    {"siphash24",  128},
    {"chacha20",   256},
};

constexpr int kCandidateKb[] = {512, 1024, 2048};

// Maps a primitive name to its expected fixed hash-key length in
// bytes. SipHash-2-4 has no internal fixed key (its keying material is
// the seed components themselves), so the expected length is 0.
std::size_t expected_hash_key_len(std::string_view name) {
    if (name == "areion256")  return 32;
    if (name == "areion512")  return 64;
    if (name == "blake2b256") return 32;
    if (name == "blake2b512") return 64;
    if (name == "blake2s")    return 32;
    if (name == "blake3")     return 32;
    if (name == "aescmac")    return 16;
    if (name == "siphash24")  return 0;
    if (name == "chacha20")   return 32;
    return 0;
}

// Builds the test plaintext (binary data including 0x00 bytes).
std::vector<std::uint8_t> build_plaintext() {
    static const char prefix[] = "any binary data, including 0x00 bytes -- ";
    std::size_t prefix_len = sizeof(prefix) - 1;
    std::vector<std::uint8_t> out(prefix_len + 256);
    std::memcpy(out.data(), prefix, prefix_len);
    for (std::size_t i = 0; i < 256; ++i) {
        out[prefix_len + i] = static_cast<std::uint8_t>(i);
    }
    return out;
}

} // namespace

TEST_CASE("persistence round-trip across every primitive and key_bits",
          "[persistence][matrix]") {
    auto plaintext = build_plaintext();

    for (const auto& spec : kCanonicalHashes) {
        for (int kb : kCandidateKb) {
            if (kb % spec.width != 0) continue;
            SECTION(std::string{"hash="} + spec.name
                    + " key_bits=" + std::to_string(kb)) {
                // Day 1 — random seeds.
                itb::Seed n{spec.name, kb};
                itb::Seed d{spec.name, kb};
                itb::Seed s{spec.name, kb};

                auto n_comps = n.components();
                auto d_comps = d.components();
                auto s_comps = s.components();
                REQUIRE(n_comps.size() * 64u == static_cast<std::size_t>(kb));

                auto n_key = n.hash_key();
                auto d_key = d.hash_key();
                auto s_key = s.hash_key();
                REQUIRE(n_key.size() == expected_hash_key_len(spec.name));

                auto ct = itb::encrypt(n, d, s, plaintext);

                // Day 2 — restore from saved material and decrypt.
                auto n2 = itb::Seed::from_components(spec.name, n_comps, n_key);
                auto d2 = itb::Seed::from_components(spec.name, d_comps, d_key);
                auto s2 = itb::Seed::from_components(spec.name, s_comps, s_key);

                auto pt = itb::decrypt(n2, d2, s2, ct);
                REQUIRE(pt == plaintext);

                // Restored seeds report identical components + key.
                REQUIRE(n2.components() == n_comps);
                REQUIRE(n2.hash_key()   == n_key);
            }
        }
    }
}

TEST_CASE("persistence random key path with empty hash_key",
          "[persistence][random_key]") {
    // 512-bit zero components — sufficient for non-SipHash primitives.
    std::vector<std::uint64_t> components(8, 0);
    std::vector<std::uint8_t>  empty_key;

    for (const auto& spec : kCanonicalHashes) {
        SECTION(std::string{"hash="} + spec.name) {
            auto seed = itb::Seed::from_components(spec.name, components,
                                                   empty_key);
            auto k = seed.hash_key();
            if (std::string_view{spec.name} == "siphash24") {
                REQUIRE(k.empty());
            } else {
                REQUIRE(k.size() == expected_hash_key_len(spec.name));
            }
        }
    }
}

TEST_CASE("persistence explicit key is preserved through rebuild",
          "[persistence][explicit_key]") {
    // BLAKE3 has a 32-byte symmetric key.
    std::vector<std::uint8_t> explicit_key(32);
    for (std::uint8_t i = 0; i < 32; ++i) {
        explicit_key[i] = i;
    }
    std::vector<std::uint64_t> components(8, 0xCAFEBABEDEADBEEFULL);

    auto seed = itb::Seed::from_components("blake3", components, explicit_key);
    auto k = seed.hash_key();
    REQUIRE(k == explicit_key);
}

TEST_CASE("persistence rejects bad hash_key length",
          "[persistence][bad_key_size]") {
    // Seven bytes is wrong for BLAKE3 (expects 32). The rebuild must
    // surface a clean error rather than panic across the FFI.
    std::vector<std::uint64_t> components(16, 0);
    std::vector<std::uint8_t>  bad_key(7, 0);
    REQUIRE_THROWS_AS(
        itb::Seed::from_components("blake3", components, bad_key),
        itb::ItbError);
}

TEST_CASE("persistence rejects non-empty hash_key for siphash24",
          "[persistence][siphash_rejects]") {
    // SipHash-2-4 takes no internal fixed key — passing one must be
    // rejected, not silently ignored.
    std::vector<std::uint64_t> components(8, 0);
    std::vector<std::uint8_t>  nonempty(16, 0);
    REQUIRE_THROWS_AS(
        itb::Seed::from_components("siphash24", components, nonempty),
        itb::ItbError);
}

TEST_CASE("persistence mixed-primitive seed trio rebuilds correctly",
          "[persistence][mixed]") {
    // Each of three seeds in a Single Ouroboros trio may use a
    // different primitive at the same native width (256 here). The
    // wire-side encrypt sees the same width across the trio (so no
    // SEED_WIDTH_MIX); persistence pairs each Seed with its own
    // (components, hash_key) record.
    auto plaintext = build_plaintext();

    itb::Seed n{"blake3",     1024};
    itb::Seed d{"blake2s",    1024};
    itb::Seed s{"blake2b256", 1024};

    auto n_comps = n.components();
    auto d_comps = d.components();
    auto s_comps = s.components();
    auto n_key   = n.hash_key();
    auto d_key   = d.hash_key();
    auto s_key   = s.hash_key();

    auto ct = itb::encrypt(n, d, s, plaintext);

    auto n2 = itb::Seed::from_components("blake3",     n_comps, n_key);
    auto d2 = itb::Seed::from_components("blake2s",    d_comps, d_key);
    auto s2 = itb::Seed::from_components("blake2b256", s_comps, s_key);

    auto pt = itb::decrypt(n2, d2, s2, ct);
    REQUIRE(pt == plaintext);
}
