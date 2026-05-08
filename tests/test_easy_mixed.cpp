// test_mixed.cpp — Mixed-mode Encryptor (per-slot PRF primitive
// selection) coverage on the high-level Easy surface.
//
// Mirrors bindings/c/tests/test_easy_mixed.c — Single + Triple
// Ouroboros round-trips through Encryptor::Mixed /
// Encryptor::Mixed3, with and without the dedicated lockSeed
// primitive in position 4 (Single) / position 8 (Triple). Per-slot
// introspection through primitive_at confirms the constructor's
// positional arguments mapped correctly into the underlying state.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xFEEDFACEDEC0DED0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

} // namespace

// ---- Mixed (Single Ouroboros, 3 seeds, optional lockSeed slot 4) ---

TEST_CASE("mixed single basic round-trip without lockSeed",
          "[mixed][single]") {
    auto enc = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "", 1024, "hmac-blake3");
    REQUIRE(enc.is_mixed());
    REQUIRE(enc.mode() == 1);
    REQUIRE(enc.seed_count() == 3);
    REQUIRE(enc.primitive() == "mixed");
    REQUIRE(enc.primitive_at(0) == "blake3");
    REQUIRE(enc.primitive_at(1) == "blake2s");
    REQUIRE(enc.primitive_at(2) == "blake2b256");

    auto plaintext = token_bytes(2048);
    auto ct = enc.encrypt(plaintext);
    auto pt = enc.decrypt(ct);
    REQUIRE(pt == plaintext);

    auto act = enc.encrypt_auth(plaintext);
    auto apt = enc.decrypt_auth(act);
    REQUIRE(apt == plaintext);
}

TEST_CASE("mixed single basic round-trip with dedicated lockSeed",
          "[mixed][single][lockseed]") {
    auto enc = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "areion256", 1024, "hmac-blake3");
    REQUIRE(enc.is_mixed());
    REQUIRE(enc.mode() == 1);
    REQUIRE(enc.seed_count() == 4);
    REQUIRE(enc.primitive_at(0) == "blake3");
    REQUIRE(enc.primitive_at(1) == "blake2s");
    REQUIRE(enc.primitive_at(2) == "blake2b256");
    REQUIRE(enc.primitive_at(3) == "areion256");

    auto plaintext = token_bytes(4096);
    auto ct = enc.encrypt_auth(plaintext);
    auto pt = enc.decrypt_auth(ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("mixed single state export-import round-trip",
          "[mixed][single][persistence]") {
    auto sender = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                        "", 1024, "hmac-blake3");
    auto plaintext = token_bytes(2048);
    auto ct = sender.encrypt_auth(plaintext);
    auto blob = sender.export_state();
    REQUIRE_FALSE(blob.empty());

    auto receiver = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                          "", 1024, "hmac-blake3");
    receiver.import_state(blob);
    auto pt = receiver.decrypt_auth(ct);
    REQUIRE(pt == plaintext);
}

// ---- Mixed3 (Triple Ouroboros, 7 seeds, optional lockSeed slot 8) --

TEST_CASE("mixed3 triple basic round-trip without lockSeed",
          "[mixed3][triple]") {
    auto enc = itb::Encryptor::Mixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "" /*no lockSeed*/, 1024, "hmac-blake3");
    REQUIRE(enc.is_mixed());
    REQUIRE(enc.mode() == 3);
    REQUIRE(enc.seed_count() == 7);

    const char* wants[] = {
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
    };
    for (int i = 0; i < 7; i++) {
        REQUIRE(enc.primitive_at(i) == wants[i]);
    }

    auto plaintext = token_bytes(2048);
    auto ct = enc.encrypt(plaintext);
    auto pt = enc.decrypt(ct);
    REQUIRE(pt == plaintext);

    auto act = enc.encrypt_auth(plaintext);
    auto apt = enc.decrypt_auth(act);
    REQUIRE(apt == plaintext);
}

TEST_CASE("mixed3 triple basic round-trip with dedicated lockSeed",
          "[mixed3][triple][lockseed]") {
    auto enc = itb::Encryptor::Mixed3(
        "blake3", "blake2s", "blake3", "blake2s",
        "blake3", "blake2s", "blake3",
        "areion256", 1024, "hmac-blake3");
    REQUIRE(enc.is_mixed());
    REQUIRE(enc.mode() == 3);
    REQUIRE(enc.seed_count() == 8);
    REQUIRE(enc.primitive_at(7) == "areion256");

    auto plaintext = token_bytes(8192);
    auto ct = enc.encrypt_auth(plaintext);
    auto pt = enc.decrypt_auth(ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("mixed3 triple state export-import round-trip with lockSeed",
          "[mixed3][triple][persistence]") {
    auto sender = itb::Encryptor::Mixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "areion256", 1024, "hmac-blake3");
    auto plaintext = token_bytes(4096);
    auto ct = sender.encrypt_auth(plaintext);
    auto blob = sender.export_state();
    REQUIRE_FALSE(blob.empty());

    auto receiver = itb::Encryptor::Mixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "areion256", 1024, "hmac-blake3");
    receiver.import_state(blob);
    auto pt = receiver.decrypt_auth(ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("non-mixed default constructor reports is_mixed=false",
          "[mixed][default]") {
    itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
    REQUIRE_FALSE(enc.is_mixed());
    REQUIRE(enc.seed_count() == 3);
    for (int i = 0; i < 3; i++) {
        REQUIRE(enc.primitive_at(i) == "blake3");
    }
}
