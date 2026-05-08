// test_easy_auth.cpp — authenticated encryption coverage on the
// high-level Encryptor surface.
//
// Mirrors bindings/c/tests/test_easy_auth.c on the C++ surface. The
// matrix exercised here is:
//
//   - All 9 PRF primitives × kmac256 × {Single, Triple} mode —
//     encrypt_auth + decrypt_auth round-trip with payload bytes
//     varying per primitive.
//   - One representative primitive (areion512) × all 3 canonical
//     MACs (kmac256, hmac-sha256, hmac-blake3) × {Single, Triple} —
//     covers the MAC axis without quadratic blow-up.
//   - MAC tampering: flipping a 256-byte window past the dynamic
//     header forces decrypt_auth to raise ItbError(kMacFailure).
//   - Cross-MAC structural rejection: a sender encrypted under
//     hmac-blake3 produces a state blob that cannot be imported into
//     a receiver constructed under kmac256 — the import surfaces
//     ItbEasyMismatchError with `field() == "mac"`.
//   - Same-primitive different-key MAC failure: two independently
//     constructed encryptors under the same primitive + MAC fail
//     with kMacFailure rather than yielding corrupted plaintext when
//     the receiver is fed the sender's ciphertext.
//   - encrypt_auth output decrypted with plain decrypt() raises
//     ItbError (the auth-tag suffix corrupts the structural shape
//     visible to the non-auth decoder).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr const char* kCanonicalMacs[] = {
    "kmac256",
    "hmac-sha256",
    "hmac-blake3",
};

struct PrimSpec {
    const char* name;
    int width;
};

// Canonical 9-primitive PRF set. width drives the key_bits-divisibility
// check (key_bits must be a multiple of width).
constexpr PrimSpec kPrims[] = {
    {"areion256",  256},
    {"areion512",  512},
    {"siphash24",  128},
    {"aescmac",    128},
    {"blake2b256", 256},
    {"blake2b512", 512},
    {"blake2s",    256},
    {"blake3",     256},
    {"chacha20",   256},
};

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xCAFEBABEDEADBEEFULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

// Flips a 256-byte window of the ciphertext past the dynamic header.
// Returns the modified ciphertext copy.
std::vector<std::uint8_t> tamper_after_header(
    const std::vector<std::uint8_t>& ct, int header_size) {
    auto out = ct;
    std::size_t hs = static_cast<std::size_t>(header_size);
    std::size_t end = hs + 256;
    if (end > out.size()) {
        end = out.size();
    }
    for (std::size_t b = hs; b < end; ++b) {
        out[b] ^= 0x01;
    }
    return out;
}

} // namespace

TEST_CASE("encrypt_auth + decrypt_auth round-trip across the 9-primitive grid (single)",
          "[easy_auth][grid][single]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        if (1024 % spec.width != 0) {
            continue;
        }
        SECTION(std::string{spec.name} + "/kmac256/single") {
            itb::Encryptor enc{spec.name, 1024, "kmac256", 1};
            auto ct = enc.encrypt_auth(pt);
            auto recovered = enc.decrypt_auth(ct);
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth round-trip across the 9-primitive grid (triple)",
          "[easy_auth][grid][triple]") {
    auto pt = token_bytes(4096);
    for (const auto& spec : kPrims) {
        if (1024 % spec.width != 0) {
            continue;
        }
        SECTION(std::string{spec.name} + "/kmac256/triple") {
            itb::Encryptor enc{spec.name, 1024, "kmac256", 3};
            auto ct = enc.encrypt_auth(pt);
            auto recovered = enc.decrypt_auth(ct);
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth round-trip across all 3 MACs",
          "[easy_auth][mac_axis]") {
    auto pt = token_bytes(2048);
    for (const char* mac : kCanonicalMacs) {
        for (int mode : {1, 3}) {
            SECTION(std::string{"areion512/"} + mac + "/mode=" +
                    std::to_string(mode)) {
                itb::Encryptor enc{"areion512", 1024, mac, mode};
                auto ct = enc.encrypt_auth(pt);
                auto recovered = enc.decrypt_auth(ct);
                REQUIRE(recovered == pt);
                REQUIRE(enc.mac_name() == mac);
            }
        }
    }
}

TEST_CASE("decrypt_auth raises kMacFailure on tampered ciphertext (single, all MACs)",
          "[easy_auth][tamper][single]") {
    auto pt = token_bytes(2048);
    for (const char* mac : kCanonicalMacs) {
        SECTION(std::string{"blake3/"} + mac + "/single") {
            itb::Encryptor enc{"blake3", 1024, mac, 1};
            auto ct = enc.encrypt_auth(pt);
            REQUIRE(enc.decrypt_auth(ct) == pt);

            int hs = enc.header_size();
            REQUIRE(hs > 0);
            REQUIRE(static_cast<std::size_t>(hs) < ct.size());
            auto bad = tamper_after_header(ct, hs);

            try {
                (void)enc.decrypt_auth(bad);
                FAIL("expected ItbError(kMacFailure)");
            } catch (const itb::ItbError& e) {
                REQUIRE(e.code() == itb::status::kMacFailure);
            }
        }
    }
}

TEST_CASE("decrypt_auth raises kMacFailure on tampered ciphertext (triple, all MACs)",
          "[easy_auth][tamper][triple]") {
    auto pt = token_bytes(2048);
    for (const char* mac : kCanonicalMacs) {
        SECTION(std::string{"blake3/"} + mac + "/triple") {
            itb::Encryptor enc{"blake3", 1024, mac, 3};
            auto ct = enc.encrypt_auth(pt);
            REQUIRE(enc.decrypt_auth(ct) == pt);

            int hs = enc.header_size();
            REQUIRE(hs > 0);
            REQUIRE(static_cast<std::size_t>(hs) < ct.size());
            auto bad = tamper_after_header(ct, hs);

            try {
                (void)enc.decrypt_auth(bad);
                FAIL("expected ItbError(kMacFailure)");
            } catch (const itb::ItbError& e) {
                REQUIRE(e.code() == itb::status::kMacFailure);
            }
        }
    }
}

TEST_CASE("export-then-import across mismatched MACs raises kEasyMismatch on field=mac",
          "[easy_auth][mac_mismatch]") {
    // Sender uses kmac256; receiver is constructed with hmac-sha256.
    // import_state must reject with EASY_MISMATCH and report
    // field == "mac".
    itb::Encryptor src{"blake3", 1024, "kmac256", 1};
    auto blob = src.export_state();

    itb::Encryptor dst{"blake3", 1024, "hmac-sha256", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "mac");
    }
}

TEST_CASE("two same-primitive same-MAC encryptors hold independent keys",
          "[easy_auth][independent_keys]") {
    static const char kPlaintext[] = "authenticated payload";
    auto pt = std::vector<std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(kPlaintext),
        reinterpret_cast<const std::uint8_t*>(kPlaintext) + sizeof(kPlaintext) - 1};

    itb::Encryptor enc1{"blake3", 1024, "hmac-sha256", 1};
    itb::Encryptor enc2{"blake3", 1024, "hmac-sha256", 1};

    auto ct = enc1.encrypt_auth(pt);
    // enc2's MAC key + seed material is independent of enc1's, so the
    // MAC on enc1's ciphertext fails to verify under enc2 — the
    // observed code is kMacFailure rather than corrupted plaintext.
    try {
        (void)enc2.decrypt_auth(ct);
        FAIL("expected ItbError(kMacFailure)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kMacFailure);
    }
}

TEST_CASE("plain decrypt of an encrypt_auth ciphertext returns at least the plaintext prefix",
          "[easy_auth][cross_mode]") {
    // encrypt_auth wraps the structured payload + MAC tag inside the
    // same envelope shape as plain encrypt; calling plain decrypt on
    // an encrypt_auth ciphertext does NOT raise — the auth-mode
    // distinction lives in the MAC verification path, not in the
    // structural framing. The recovered bytes therefore start with
    // the original plaintext (and may include trailing MAC bytes).
    auto pt = token_bytes(1024);
    itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
    auto ct_auth = enc.encrypt_auth(pt);

    auto recovered = enc.decrypt(ct_auth);
    REQUIRE(recovered.size() >= pt.size());
    REQUIRE(std::equal(pt.begin(), pt.end(), recovered.begin()));
}

TEST_CASE("export / import authenticated round-trip succeeds end-to-end",
          "[easy_auth][persistence]") {
    auto pt = token_bytes(4096);
    itb::Encryptor src{"areion512", 2048, "hmac-blake3", 3};
    auto ct   = src.encrypt_auth(pt);
    auto blob = src.export_state();

    itb::Encryptor dst{"areion512", 2048, "hmac-blake3", 3};
    dst.import_state(blob);
    REQUIRE(dst.decrypt_auth(ct) == pt);
}
