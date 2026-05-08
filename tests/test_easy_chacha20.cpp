// test_chacha20.cpp — ChaCha20-focused Encryptor (Easy Mode) coverage.
//
// Mirrors bindings/c/tests/test_easy_chacha20.c — Single + Triple
// Ouroboros round-trips (encrypt / decrypt + encrypt_auth /
// decrypt_auth) across the size grid 32 B / 4 KiB / 64 KiB.
// ChaCha20 ships at a single width (256-bit); the alternate
// key_bits exercise here is 2048 (the maximum supported width
// divisible by 256). A cross-encryptor tamper-resistance pass
// closes the suite.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xCA0CCA20FACE0FF0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr const char* kPrimitive = "chacha20";
constexpr int kDefaultKeyBits    = 1024;
constexpr int kAltKeyBits        = 2048;

const std::size_t kSizes[] = {32u, 4096u, 65536u};

} // namespace

TEST_CASE("chacha20 single ouroboros round-trip", "[chacha20][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Encryptor enc{kPrimitive, kDefaultKeyBits, "", 1};
            REQUIRE(enc.primitive() == kPrimitive);
            REQUIRE(enc.mode() == 1);
            auto ct = enc.encrypt(plaintext);
            auto pt = enc.decrypt(ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 single ouroboros auth round-trip",
          "[chacha20][single][auth]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Encryptor enc{kPrimitive, kDefaultKeyBits, "", 1};
            auto ct = enc.encrypt_auth(plaintext);
            auto pt = enc.decrypt_auth(ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 triple ouroboros round-trip", "[chacha20][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Encryptor enc{kPrimitive, kDefaultKeyBits, "", 3};
            REQUIRE(enc.mode() == 3);
            REQUIRE(enc.seed_count() == 7);
            auto ct = enc.encrypt(plaintext);
            auto pt = enc.decrypt(ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 triple ouroboros auth round-trip",
          "[chacha20][triple][auth]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Encryptor enc{kPrimitive, kDefaultKeyBits, "", 3};
            auto ct = enc.encrypt_auth(plaintext);
            auto pt = enc.decrypt_auth(ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 alternate key_bits 2048", "[chacha20][altkb]") {
    auto plaintext = token_bytes(2048);
    SECTION("single") {
        itb::Encryptor enc{kPrimitive, kAltKeyBits, "", 1};
        REQUIRE(enc.key_bits() == kAltKeyBits);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(plaintext)) == plaintext);
    }
    SECTION("triple") {
        itb::Encryptor enc{kPrimitive, kAltKeyBits, "", 3};
        REQUIRE(enc.key_bits() == kAltKeyBits);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(plaintext)) == plaintext);
    }
}

TEST_CASE("chacha20 tamper resistance via export-import",
          "[chacha20][tamper]") {
    auto plaintext = token_bytes(1024);

    itb::Encryptor src{kPrimitive, kDefaultKeyBits, "", 1};
    auto blob = src.export_state();
    auto ct   = src.encrypt_auth(plaintext);

    int hsize = src.header_size();
    REQUIRE(hsize > 0);
    REQUIRE(static_cast<std::size_t>(hsize) < ct.size());
    // Flip a 256-byte window beyond the header for deterministic
    // tamper detection across primitive / nonce combinations.
    std::size_t end = static_cast<std::size_t>(hsize) + 256;
    if (end > ct.size()) end = ct.size();
    for (std::size_t b = static_cast<std::size_t>(hsize); b < end; b++) {
        ct[b] ^= 0x01;
    }

    itb::Encryptor dst{kPrimitive, kDefaultKeyBits, "", 1};
    dst.import_state(blob);
    REQUIRE_THROWS_AS(dst.decrypt_auth(ct), itb::ItbError);
}
