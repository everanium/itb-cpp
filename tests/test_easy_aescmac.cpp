// test_aescmac.cpp — AES-CMAC-focused Encryptor (Easy Mode) coverage.
//
// Mirrors bindings/c/tests/test_easy_aescmac.c — Single + Triple
// Ouroboros round-trips (encrypt / decrypt + encrypt_auth /
// decrypt_auth) across the size grid 32 B / 4 KiB / 64 KiB, plus a
// cross-encryptor tamper-resistance pass over the Export / Import
// surface. AES-CMAC ships only at 128-bit width; the alternate
// key_bits exercise here is 2048 (the maximum supported width that
// is divisible by 128).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

// Deterministic counter-driven byte filler. Mirrors the splitmix-style
// generator used by the C-binding test fixtures so payloads of a given
// length are reproducible across reruns within a single process.
std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xDEADBEEFCAFEBABEULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr const char* kPrimitive = "aescmac";
constexpr int kDefaultKeyBits    = 1024;
constexpr int kAltKeyBits        = 2048; // 2048 % 128 == 0

const std::size_t kSizes[] = {32u, 4096u, 65536u};

} // namespace

TEST_CASE("aescmac single ouroboros round-trip", "[aescmac][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);

            itb::Encryptor enc{kPrimitive, kDefaultKeyBits, "", 1};
            REQUIRE(enc.mode() == 1);
            REQUIRE(enc.primitive() == kPrimitive);

            auto ct = enc.encrypt(plaintext);
            REQUIRE_FALSE(ct.empty());
            auto pt = enc.decrypt(ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("aescmac single ouroboros auth round-trip", "[aescmac][single][auth]") {
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

TEST_CASE("aescmac triple ouroboros round-trip", "[aescmac][triple]") {
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

TEST_CASE("aescmac triple ouroboros auth round-trip", "[aescmac][triple][auth]") {
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

TEST_CASE("aescmac alternate key_bits round-trip", "[aescmac][altkb]") {
    auto plaintext = token_bytes(2048);

    SECTION("single 2048-bit") {
        itb::Encryptor enc{kPrimitive, kAltKeyBits, "", 1};
        REQUIRE(enc.key_bits() == kAltKeyBits);
        auto ct = enc.encrypt_auth(plaintext);
        auto pt = enc.decrypt_auth(ct);
        REQUIRE(pt == plaintext);
    }
    SECTION("triple 2048-bit") {
        itb::Encryptor enc{kPrimitive, kAltKeyBits, "", 3};
        REQUIRE(enc.key_bits() == kAltKeyBits);
        auto ct = enc.encrypt_auth(plaintext);
        auto pt = enc.decrypt_auth(ct);
        REQUIRE(pt == plaintext);
    }
}

TEST_CASE("aescmac tamper resistance via export-import", "[aescmac][tamper]") {
    auto plaintext = token_bytes(1024);

    itb::Encryptor src{kPrimitive, kDefaultKeyBits, "", 1};
    auto blob = src.export_state();
    auto ct   = src.encrypt_auth(plaintext);

    // Flip a byte beyond the unauthenticated header so the MAC catches it.
    int hsize = src.header_size();
    REQUIRE(hsize > 0);
    REQUIRE(static_cast<std::size_t>(hsize) < ct.size());
    // Flip a 256-byte window beyond the header, matching the C-binding
    // tamper pattern. A single-byte flip can leave the MAC happy for
    // some payload-layout / nonce combinations; the wider window
    // provides deterministic tamper detection.
    std::size_t end = static_cast<std::size_t>(hsize) + 256;
    if (end > ct.size()) end = ct.size();
    for (std::size_t b = static_cast<std::size_t>(hsize); b < end; b++) {
        ct[b] ^= 0x01;
    }

    itb::Encryptor dst{kPrimitive, kDefaultKeyBits, "", 1};
    dst.import_state(blob);

    REQUIRE_THROWS_AS(dst.decrypt_auth(ct), itb::ItbError);
}
