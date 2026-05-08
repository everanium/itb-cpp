// test_blake2b.cpp — BLAKE2b-focused Encryptor (Easy Mode) coverage.
//
// Mirrors bindings/c/tests/test_easy_blake2b.c — Single + Triple
// Ouroboros round-trips (encrypt / decrypt + encrypt_auth /
// decrypt_auth) across the size grid 32 B / 4 KiB / 64 KiB. Two
// independent TEST_CASE blocks pair BLAKE2b-256 with an alternate
// 512-bit key_bits and BLAKE2b-512 with an alternate 2048-bit
// key_bits. A cross-encryptor tamper-resistance pass closes each
// primitive's TEST_CASE set.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xB2B12480DEADBEEFULL;
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

// ---- BLAKE2b-256 (256-bit width) ---------------------------------

TEST_CASE("blake2b256 single ouroboros round-trip", "[blake2b256][single]") {
    run_single_roundtrip("blake2b256", 1024);
}

TEST_CASE("blake2b256 single ouroboros auth round-trip",
          "[blake2b256][single][auth]") {
    run_single_auth_roundtrip("blake2b256", 1024);
}

TEST_CASE("blake2b256 triple ouroboros round-trip", "[blake2b256][triple]") {
    run_triple_roundtrip("blake2b256", 1024);
}

TEST_CASE("blake2b256 triple ouroboros auth round-trip",
          "[blake2b256][triple][auth]") {
    run_triple_auth_roundtrip("blake2b256", 1024);
}

TEST_CASE("blake2b256 alternate key_bits 512", "[blake2b256][altkb]") {
    SECTION("single") {
        itb::Encryptor enc{"blake2b256", 512, "", 1};
        REQUIRE(enc.key_bits() == 512);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
    SECTION("triple") {
        itb::Encryptor enc{"blake2b256", 512, "", 3};
        REQUIRE(enc.key_bits() == 512);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
}

TEST_CASE("blake2b256 tamper resistance via export-import",
          "[blake2b256][tamper]") {
    run_tamper_check("blake2b256", 1024);
}

// ---- BLAKE2b-512 (512-bit width) ---------------------------------

TEST_CASE("blake2b512 single ouroboros round-trip", "[blake2b512][single]") {
    run_single_roundtrip("blake2b512", 1024);
}

TEST_CASE("blake2b512 single ouroboros auth round-trip",
          "[blake2b512][single][auth]") {
    run_single_auth_roundtrip("blake2b512", 1024);
}

TEST_CASE("blake2b512 triple ouroboros round-trip", "[blake2b512][triple]") {
    run_triple_roundtrip("blake2b512", 1024);
}

TEST_CASE("blake2b512 triple ouroboros auth round-trip",
          "[blake2b512][triple][auth]") {
    run_triple_auth_roundtrip("blake2b512", 1024);
}

TEST_CASE("blake2b512 alternate key_bits 2048", "[blake2b512][altkb]") {
    SECTION("single") {
        itb::Encryptor enc{"blake2b512", 2048, "", 1};
        REQUIRE(enc.key_bits() == 2048);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
    SECTION("triple") {
        itb::Encryptor enc{"blake2b512", 2048, "", 3};
        REQUIRE(enc.key_bits() == 2048);
        auto pt = token_bytes(2048);
        REQUIRE(enc.decrypt_auth(enc.encrypt_auth(pt)) == pt);
    }
}

TEST_CASE("blake2b512 tamper resistance via export-import",
          "[blake2b512][tamper]") {
    run_tamper_check("blake2b512", 1024);
}
