// test_chacha20.cpp — ChaCha20 low-level cipher coverage.
//
// Mirrors bindings/c/tests/test_chacha20.c on the C++ free-function
// cipher surface. ChaCha20 ships at a single native width (256).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xDEADBEEFCAFEBABEULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr const char* kPrimitive = "chacha20";
constexpr int kChacha20Width     = 256;
constexpr int kDefaultKeyBits    = 1024;
constexpr int kAltKeyBits        = 2048; // 2048 % 256 == 0

constexpr const char* kMacs[] = {"kmac256", "hmac-sha256", "hmac-blake3"};

const std::size_t kSizes[] = {32u, 4096u, 65536u};

} // namespace

TEST_CASE("chacha20 single ouroboros round-trip", "[chacha20][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Seed n{kPrimitive, kDefaultKeyBits};
            itb::Seed d{kPrimitive, kDefaultKeyBits};
            itb::Seed s{kPrimitive, kDefaultKeyBits};
            auto ct = itb::encrypt(n, d, s, plaintext);
            REQUIRE(ct.size() > sz);
            auto pt = itb::decrypt(n, d, s, ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 triple ouroboros round-trip", "[chacha20][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = token_bytes(sz);
            itb::Seed n {kPrimitive, kDefaultKeyBits};
            itb::Seed d1{kPrimitive, kDefaultKeyBits};
            itb::Seed d2{kPrimitive, kDefaultKeyBits};
            itb::Seed d3{kPrimitive, kDefaultKeyBits};
            itb::Seed s1{kPrimitive, kDefaultKeyBits};
            itb::Seed s2{kPrimitive, kDefaultKeyBits};
            itb::Seed s3{kPrimitive, kDefaultKeyBits};
            auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3, plaintext);
            auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
            REQUIRE(pt == plaintext);
        }
    }
}

TEST_CASE("chacha20 alternate key_bits round-trip", "[chacha20][altkb]") {
    auto plaintext = token_bytes(2048);

    SECTION("single 2048-bit") {
        itb::Seed n{kPrimitive, kAltKeyBits};
        itb::Seed d{kPrimitive, kAltKeyBits};
        itb::Seed s{kPrimitive, kAltKeyBits};
        auto ct = itb::encrypt(n, d, s, plaintext);
        auto pt = itb::decrypt(n, d, s, ct);
        REQUIRE(pt == plaintext);
    }
    SECTION("triple 2048-bit") {
        itb::Seed n {kPrimitive, kAltKeyBits};
        itb::Seed d1{kPrimitive, kAltKeyBits};
        itb::Seed d2{kPrimitive, kAltKeyBits};
        itb::Seed d3{kPrimitive, kAltKeyBits};
        itb::Seed s1{kPrimitive, kAltKeyBits};
        itb::Seed s2{kPrimitive, kAltKeyBits};
        itb::Seed s3{kPrimitive, kAltKeyBits};
        auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3, plaintext);
        auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
        REQUIRE(pt == plaintext);
    }
}

TEST_CASE("chacha20 auth round-trip across MACs", "[chacha20][auth]") {
    auto plaintext = token_bytes(1024);
    std::vector<std::uint8_t> key(32, 0x42);

    for (const char* mac_name : kMacs) {
        SECTION(std::string{"mac="} + mac_name) {
            itb::Mac mac{mac_name, key};
            itb::Seed n{kPrimitive, kDefaultKeyBits};
            itb::Seed d{kPrimitive, kDefaultKeyBits};
            itb::Seed s{kPrimitive, kDefaultKeyBits};

            auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
            auto pt = itb::decrypt_auth(n, d, s, mac, ct);
            REQUIRE(pt == plaintext);

            int hsize = itb::header_size();
            REQUIRE(hsize > 0);
            std::size_t end = static_cast<std::size_t>(hsize) + 256;
            if (end > ct.size()) end = ct.size();
            for (std::size_t b = static_cast<std::size_t>(hsize); b < end; ++b) {
                ct[b] ^= 0x01;
            }
            try {
                (void) itb::decrypt_auth(n, d, s, mac, ct);
                FAIL("expected MAC_FAILURE on tampered ciphertext");
            } catch (const itb::ItbError& e) {
                REQUIRE(e.code() == itb::status::kMacFailure);
            }
        }
    }
}

TEST_CASE("chacha20 cross-seed decrypt does not recover plaintext",
          "[chacha20][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    itb::Seed d{kPrimitive, kDefaultKeyBits};
    itb::Seed s{kPrimitive, kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // The unauthenticated low-level decrypt may surface an ItbError or
    // return garbage that survived the structural checks; either is
    // acceptable. Recovering the original plaintext is forbidden.
    itb::Seed n2{kPrimitive, kDefaultKeyBits};
    itb::Seed d2{kPrimitive, kDefaultKeyBits};
    itb::Seed s2{kPrimitive, kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {}
    REQUIRE_FALSE(recovered);
}

TEST_CASE("chacha20 seed invariants", "[chacha20][invariants]") {
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    REQUIRE(n.width() == kChacha20Width);
    REQUIRE(n.hash_name() == kPrimitive);
    REQUIRE(n.hash_key().size() == 32u);
}
