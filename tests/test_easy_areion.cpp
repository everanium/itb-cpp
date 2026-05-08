// test_areion.cpp — Areion-SoEM-focused Encryptor (Easy Mode) coverage.
//
// Mirrors bindings/c/tests/test_easy_areion.c — Single + Triple
// Ouroboros round-trips (encrypt / decrypt + encrypt_auth /
// decrypt_auth) across the size grid 32 B / 4 KiB / 64 KiB. Two
// independent TEST_CASE blocks pair Areion-SoEM-256 with an
// alternate 512-bit key_bits (only multiples of 256), and
// Areion-SoEM-512 with an alternate 2048-bit key_bits (only
// multiples of 512). A cross-encryptor tamper-resistance pass
// closes each primitive's TEST_CASE set.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0x01EA0CDEC2DC0DE0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

const std::size_t kSizes[] = {32u, 4096u, 65536u};

void run_single_roundtrip(const char* primitive, int key_bits) {
    for (std::size_t sz : kSizes) {
        auto plaintext = token_bytes(sz);
        itb::Encryptor enc{primitive, key_bits, "", 1};
        REQUIRE(enc.primitive() == primitive);
        REQUIRE(enc.mode() == 1);
        auto ct = enc.encrypt(plaintext);
        auto pt = enc.decrypt(ct);
        REQUIRE(pt == plaintext);
    }
}

void run_single_auth_roundtrip(const char* primitive, int key_bits) {
    for (std::size_t sz : kSizes) {
        auto plaintext = token_bytes(sz);
        itb::Encryptor enc{primitive, key_bits, "", 1};
        auto ct = enc.encrypt_auth(plaintext);
        auto pt = enc.decrypt_auth(ct);
        REQUIRE(pt == plaintext);
    }
}

void run_triple_roundtrip(const char* primitive, int key_bits) {
    for (std::size_t sz : kSizes) {
        auto plaintext = token_bytes(sz);
        itb::Encryptor enc{primitive, key_bits, "", 3};
        REQUIRE(enc.mode() == 3);
        REQUIRE(enc.seed_count() == 7);
        auto ct = enc.encrypt(plaintext);
        auto pt = enc.decrypt(ct);
        REQUIRE(pt == plaintext);
    }
}

void run_triple_auth_roundtrip(const char* primitive, int key_bits) {
    for (std::size_t sz : kSizes) {
        auto plaintext = token_bytes(sz);
        itb::Encryptor enc{primitive, key_bits, "", 3};
        auto ct = enc.encrypt_auth(plaintext);
        auto pt = enc.decrypt_auth(ct);
        REQUIRE(pt == plaintext);
    }
}

void run_tamper_check(const char* primitive, int key_bits) {
    auto plaintext = token_bytes(1024);
    itb::Encryptor src{primitive, key_bits, "", 1};
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

    itb::Encryptor dst{primitive, key_bits, "", 1};
    dst.import_state(blob);
    REQUIRE_THROWS_AS(dst.decrypt_auth(ct), itb::ItbError);
}

} // namespace

// ---- Areion-SoEM-256 (256-bit width) -----------------------------

TEST_CASE("areion256 single ouroboros round-trip", "[areion256][single]") {
    run_single_roundtrip("areion256", 1024);
}

TEST_CASE("areion256 single ouroboros auth round-trip",
          "[areion256][single][auth]") {
    run_single_auth_roundtrip("areion256", 1024);
}

TEST_CASE("areion256 triple ouroboros round-trip", "[areion256][triple]") {
    run_triple_roundtrip("areion256", 1024);
}

TEST_CASE("areion256 triple ouroboros auth round-trip",
          "[areion256][triple][auth]") {
    run_triple_auth_roundtrip("areion256", 1024);
}

TEST_CASE("areion256 alternate key_bits 512", "[areion256][altkb]") {
    SECTION("single") {
        itb::Encryptor enc{"areion256", 512, "", 1};
        REQUIRE(enc.key_bits() == 512);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
    SECTION("triple") {
        itb::Encryptor enc{"areion256", 512, "", 3};
        REQUIRE(enc.key_bits() == 512);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
}

TEST_CASE("areion256 tamper resistance via export-import",
          "[areion256][tamper]") {
    run_tamper_check("areion256", 1024);
}

// ---- Areion-SoEM-512 (512-bit width) -----------------------------

TEST_CASE("areion512 single ouroboros round-trip", "[areion512][single]") {
    run_single_roundtrip("areion512", 1024);
}

TEST_CASE("areion512 single ouroboros auth round-trip",
          "[areion512][single][auth]") {
    run_single_auth_roundtrip("areion512", 1024);
}

TEST_CASE("areion512 triple ouroboros round-trip", "[areion512][triple]") {
    run_triple_roundtrip("areion512", 1024);
}

TEST_CASE("areion512 triple ouroboros auth round-trip",
          "[areion512][triple][auth]") {
    run_triple_auth_roundtrip("areion512", 1024);
}

TEST_CASE("areion512 alternate key_bits 2048", "[areion512][altkb]") {
    SECTION("single") {
        itb::Encryptor enc{"areion512", 2048, "", 1};
        REQUIRE(enc.key_bits() == 2048);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
    SECTION("triple") {
        itb::Encryptor enc{"areion512", 2048, "", 3};
        REQUIRE(enc.key_bits() == 2048);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
}

TEST_CASE("areion512 tamper resistance via export-import",
          "[areion512][tamper]") {
    run_tamper_check("areion512", 1024);
}
