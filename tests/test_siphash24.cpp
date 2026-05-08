// test_siphash24.cpp — SipHash-2-4 low-level cipher coverage.
//
// Mirrors bindings/c/tests/test_siphash24.c on the C++ free-function
// cipher surface. SipHash-2-4 ships at a single native width (128) and
// has no internal fixed key — the keying material is the per-call seed
// components themselves — so `Seed::hash_key()` returns an empty
// vector and the persistence path stores empty bytes for the hash key.

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

constexpr const char* kPrimitive = "siphash24";
constexpr int kSiphashWidth      = 128;
constexpr int kDefaultKeyBits    = 1024;
// 512 % 128 == 0 — exercises the lower bound; 2048 % 128 == 0 too.
constexpr int kAltKeyBitsLow     = 512;

constexpr const char* kMacs[] = {"kmac256", "hmac-sha256", "hmac-blake3"};

const std::size_t kSizes[] = {32u, 4096u, 65536u};

} // namespace

TEST_CASE("siphash24 single ouroboros round-trip", "[siphash24][single]") {
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

TEST_CASE("siphash24 triple ouroboros round-trip", "[siphash24][triple]") {
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

TEST_CASE("siphash24 alternate key_bits round-trip", "[siphash24][altkb]") {
    auto plaintext = token_bytes(2048);

    SECTION("single 512-bit") {
        itb::Seed n{kPrimitive, kAltKeyBitsLow};
        itb::Seed d{kPrimitive, kAltKeyBitsLow};
        itb::Seed s{kPrimitive, kAltKeyBitsLow};
        auto ct = itb::encrypt(n, d, s, plaintext);
        auto pt = itb::decrypt(n, d, s, ct);
        REQUIRE(pt == plaintext);
    }
    SECTION("triple 512-bit") {
        itb::Seed n {kPrimitive, kAltKeyBitsLow};
        itb::Seed d1{kPrimitive, kAltKeyBitsLow};
        itb::Seed d2{kPrimitive, kAltKeyBitsLow};
        itb::Seed d3{kPrimitive, kAltKeyBitsLow};
        itb::Seed s1{kPrimitive, kAltKeyBitsLow};
        itb::Seed s2{kPrimitive, kAltKeyBitsLow};
        itb::Seed s3{kPrimitive, kAltKeyBitsLow};
        auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3, plaintext);
        auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
        REQUIRE(pt == plaintext);
    }
}

TEST_CASE("siphash24 auth round-trip across MACs", "[siphash24][auth]") {
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

TEST_CASE("siphash24 cross-seed decrypt does not recover plaintext",
          "[siphash24][cross]") {
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

TEST_CASE("siphash24 seed invariants", "[siphash24][invariants]") {
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    REQUIRE(n.width() == kSiphashWidth);
    REQUIRE(n.hash_name() == kPrimitive);
    // SipHash-2-4 has no internal fixed key — the keying material is
    // the seed components themselves, so hash_key returns empty.
    REQUIRE(n.hash_key().empty());
}

TEST_CASE("siphash24 from_components empty hash_key path",
          "[siphash24][persistence]") {
    auto plaintext = token_bytes(256);
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    itb::Seed d{kPrimitive, kDefaultKeyBits};
    itb::Seed s{kPrimitive, kDefaultKeyBits};

    auto ct = itb::encrypt(n, d, s, plaintext);

    auto n_comps = n.components();
    auto d_comps = d.components();
    auto s_comps = s.components();
    auto n_key   = n.hash_key();
    auto d_key   = d.hash_key();
    auto s_key   = s.hash_key();
    REQUIRE(n_key.empty());
    REQUIRE(d_key.empty());
    REQUIRE(s_key.empty());

    itb::Seed n2 = itb::Seed::from_components(kPrimitive, n_comps, n_key);
    itb::Seed d2 = itb::Seed::from_components(kPrimitive, d_comps, d_key);
    itb::Seed s2 = itb::Seed::from_components(kPrimitive, s_comps, s_key);

    auto pt = itb::decrypt(n2, d2, s2, ct);
    REQUIRE(pt == plaintext);
}
