// test_easy_roundtrip.cpp — end-to-end round-trip stress on the
// high-level Encryptor surface.
//
// Mirrors bindings/c/tests/test_easy_roundtrip.c on the C++ surface,
// covering:
//
//   - The full canonical primitive set × {Single, Triple} × {512, 1024, 2048}-bit
//     key_bits grid (filtered to widths whose key_bits is a multiple
//     of the primitive's native width). Both encrypt + decrypt and
//     encrypt_auth + decrypt_auth flow through the round-trip
//     assertion.
//   - Multiple payload sizes (32 B, 1 KiB, 16 KiB, 1 MiB) on one
//     representative primitive (blake3) to catch buffer-management
//     regressions at large input.
//   - 1024-byte payload at every Single combination across the canonical primitive set — a
//     consistent per-primitive smoke at moderate size.
//   - Round-trip stability: 100 sequential encrypt + decrypt on the
//     same Encryptor still recovers plaintext on the last iteration
//     (regression guard for the C-binding's per-instance output buffer
//     cache).
//   - Repeatability + nonce uniqueness: two encrypt() calls on the
//     same plaintext under the same Encryptor produce different
//     ciphertexts (fresh nonce per call) but both decrypt to the
//     same plaintext.
//   - Malformed-input rejection on the constructor: bad primitive,
//     bad MAC, bad key_bits, bad mode all surface as a thrown
//     ItbError before any state is created.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

struct PrimSpec {
    const char* name;
    int width;
};

constexpr PrimSpec kPrims[] = {
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

constexpr int kCandidateKeyBits[] = {512, 1024, 2048};

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xF00DCAFEBAADF00DULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

} // namespace

TEST_CASE("encrypt + decrypt round-trip across the every-primitive × 3-key_bits grid (single)",
          "[easy_roundtrip][grid][single]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        for (int kb : kCandidateKeyBits) {
            if (kb % spec.width != 0) {
                continue;
            }
            SECTION(std::string{spec.name} + "/kb=" + std::to_string(kb)) {
                itb::Encryptor enc{spec.name, kb, "kmac256", 1};
                REQUIRE(enc.key_bits() == kb);
                REQUIRE(enc.primitive() == spec.name);

                auto ct = enc.encrypt(pt);
                REQUIRE(ct.size() > pt.size());
                auto recovered = enc.decrypt(ct);
                REQUIRE(recovered == pt);
            }
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth round-trip across the every-primitive × 3-key_bits grid (single)",
          "[easy_roundtrip][grid][single][auth]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        for (int kb : kCandidateKeyBits) {
            if (kb % spec.width != 0) {
                continue;
            }
            SECTION(std::string{spec.name} + "/kb=" + std::to_string(kb)) {
                itb::Encryptor enc{spec.name, kb, "kmac256", 1};
                auto ct = enc.encrypt_auth(pt);
                auto recovered = enc.decrypt_auth(ct);
                REQUIRE(recovered == pt);
            }
        }
    }
}

TEST_CASE("encrypt + decrypt round-trip across the every-primitive × 3-key_bits grid (triple)",
          "[easy_roundtrip][grid][triple]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        for (int kb : kCandidateKeyBits) {
            if (kb % spec.width != 0) {
                continue;
            }
            SECTION(std::string{spec.name} + "/kb=" + std::to_string(kb)) {
                itb::Encryptor enc{spec.name, kb, "kmac256", 3};
                REQUIRE(enc.mode() == 3);
                REQUIRE(enc.seed_count() == 7);

                auto ct = enc.encrypt(pt);
                auto recovered = enc.decrypt(ct);
                REQUIRE(recovered == pt);
            }
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth round-trip across the every-primitive × 3-key_bits grid (triple)",
          "[easy_roundtrip][grid][triple][auth]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        for (int kb : kCandidateKeyBits) {
            if (kb % spec.width != 0) {
                continue;
            }
            SECTION(std::string{spec.name} + "/kb=" + std::to_string(kb)) {
                itb::Encryptor enc{spec.name, kb, "kmac256", 3};
                auto ct = enc.encrypt_auth(pt);
                auto recovered = enc.decrypt_auth(ct);
                REQUIRE(recovered == pt);
            }
        }
    }
}

TEST_CASE("Encryptor round-trips across multiple payload sizes",
          "[easy_roundtrip][payload_sizes]") {
    static const std::size_t kSizes[] = {
        32u,
        1024u,
        16u * 1024u,
        1024u * 1024u,
    };
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto pt = token_bytes(sz);
            itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
            auto ct = enc.encrypt(pt);
            auto recovered = enc.decrypt(ct);
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("Encryptor round-trip is stable over 100 sequential iterations",
          "[easy_roundtrip][stability]") {
    auto pt = token_bytes(1024);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    bool ok_all = true;
    for (int i = 0; i < 100; ++i) {
        auto ct = enc.encrypt(pt);
        auto recovered = enc.decrypt(ct);
        if (recovered != pt) {
            ok_all = false;
            break;
        }
    }
    REQUIRE(ok_all);
}

TEST_CASE("two encrypt calls on the same plaintext yield different ciphertexts but the same recovered plaintext",
          "[easy_roundtrip][nonce_unique]") {
    auto pt = token_bytes(1024);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    auto ct1 = enc.encrypt(pt);
    auto ct2 = enc.encrypt(pt);

    // Both ciphertexts cover the same plaintext, so their lengths
    // match.
    REQUIRE(ct1.size() == ct2.size());
    // The nonce field occupies the first nonce_bits/8 bytes of the
    // header. Two successive encrypt() calls draw fresh nonces, so the
    // nonce regions of ct1 and ct2 must differ.
    int nb = enc.nonce_bits();
    std::size_t nbytes = static_cast<std::size_t>(nb) / 8u;
    REQUIRE(nbytes > 0);
    REQUIRE(nbytes < ct1.size());
    bool nonce_differs = false;
    for (std::size_t i = 0; i < nbytes; ++i) {
        if (ct1[i] != ct2[i]) {
            nonce_differs = true;
            break;
        }
    }
    REQUIRE(nonce_differs);

    REQUIRE(enc.decrypt(ct1) == pt);
    REQUIRE(enc.decrypt(ct2) == pt);
}

TEST_CASE("constructor rejects an unknown primitive",
          "[easy_roundtrip][bad][primitive]") {
    REQUIRE_THROWS_AS(
        (itb::Encryptor{"nonsense-hash", 1024, "kmac256", 1}),
        itb::ItbError);
}

TEST_CASE("constructor rejects an unknown MAC",
          "[easy_roundtrip][bad][mac]") {
    REQUIRE_THROWS_AS(
        (itb::Encryptor{"blake3", 1024, "nonsense-mac", 1}),
        itb::ItbError);
}

TEST_CASE("constructor rejects key_bits values outside the supported set",
          "[easy_roundtrip][bad][keybits]") {
    static const int kBad[] = {256, 511, 999, 2049};
    for (int kb : kBad) {
        SECTION(std::string{"key_bits="} + std::to_string(kb)) {
            REQUIRE_THROWS_AS(
                (itb::Encryptor{"blake3", kb, "kmac256", 1}),
                itb::ItbError);
        }
    }
}

TEST_CASE("constructor rejects mode values outside the {1, 3} set",
          "[easy_roundtrip][bad][mode]") {
    try {
        itb::Encryptor enc{"blake3", 1024, "kmac256", 2};
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("seed_count reflects mode for both Single and Triple",
          "[easy_roundtrip][seed_count]") {
    SECTION("single") {
        itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
        REQUIRE(enc.seed_count() == 3);
    }
    SECTION("triple") {
        itb::Encryptor enc{"blake3", 1024, "kmac256", 3};
        REQUIRE(enc.seed_count() == 7);
    }
}

TEST_CASE("string_view encrypt overload round-trips",
          "[easy_roundtrip][string_view]") {
    static const char kPayload[] = "hello bytearray";
    std::string_view sv{kPayload, sizeof(kPayload) - 1};
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    auto ct = enc.encrypt(sv);
    auto recovered = enc.decrypt(ct);
    auto expected = std::vector<std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(sv.data()),
        reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size())};
    REQUIRE(recovered == expected);
}
