// test_blake2b.cpp — BLAKE2b-{256,512} low-level cipher coverage.
//
// Mirrors bindings/c/tests/test_blake2b.c on the C++ free-function
// cipher surface. BLAKE2b ships at two native widths (256 and 512);
// each is exercised in its own TEST_CASE block.

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

constexpr int kDefaultKeyBits = 1024;
constexpr int kMaxKeyBits     = 2048;

const std::size_t kSizes[] = {32u, 4096u, 65536u};

constexpr const char* kMacs[] = {"kmac256", "hmac-sha256", "hmac-blake3"};

void run_single_roundtrip(const char* prim, int kb, std::size_t sz) {
    auto plaintext = token_bytes(sz);
    itb::Seed n{prim, kb};
    itb::Seed d{prim, kb};
    itb::Seed s{prim, kb};
    auto ct = itb::encrypt(n, d, s, plaintext);
    REQUIRE(ct.size() > sz);
    auto pt = itb::decrypt(n, d, s, ct);
    REQUIRE(pt == plaintext);
}

void run_triple_roundtrip(const char* prim, int kb, std::size_t sz) {
    auto plaintext = token_bytes(sz);
    itb::Seed n {prim, kb};
    itb::Seed d1{prim, kb};
    itb::Seed d2{prim, kb};
    itb::Seed d3{prim, kb};
    itb::Seed s1{prim, kb};
    itb::Seed s2{prim, kb};
    itb::Seed s3{prim, kb};
    auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3, plaintext);
    auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
    REQUIRE(pt == plaintext);
}

void run_auth_roundtrip(const char* prim, int kb, const char* mac_name) {
    auto plaintext = token_bytes(1024);
    std::vector<std::uint8_t> key(32, 0x42);
    itb::Mac mac{mac_name, key};
    itb::Seed n{prim, kb};
    itb::Seed d{prim, kb};
    itb::Seed s{prim, kb};

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

} // namespace

// ---- blake2b256 (width 256) --------------------------------------

TEST_CASE("blake2b256 single ouroboros round-trip", "[blake2b][blake2b256][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_single_roundtrip("blake2b256", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("blake2b256 triple ouroboros round-trip", "[blake2b][blake2b256][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_triple_roundtrip("blake2b256", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("blake2b256 alternate key_bits round-trip", "[blake2b][blake2b256][altkb]") {
    // 2048 % 256 == 0
    SECTION("single 2048-bit") {
        run_single_roundtrip("blake2b256", kMaxKeyBits, 2048);
    }
    SECTION("triple 2048-bit") {
        run_triple_roundtrip("blake2b256", kMaxKeyBits, 2048);
    }
}

TEST_CASE("blake2b256 auth round-trip across MACs", "[blake2b][blake2b256][auth]") {
    for (const char* mac_name : kMacs) {
        SECTION(std::string{"mac="} + mac_name) {
            run_auth_roundtrip("blake2b256", kDefaultKeyBits, mac_name);
        }
    }
}

TEST_CASE("blake2b256 cross-seed decrypt does not recover plaintext",
          "[blake2b][blake2b256][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{"blake2b256", kDefaultKeyBits};
    itb::Seed d{"blake2b256", kDefaultKeyBits};
    itb::Seed s{"blake2b256", kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // The unauthenticated low-level decrypt may surface an ItbError or
    // return garbage that survived the structural checks; either is
    // acceptable. Recovering the original plaintext is forbidden.
    itb::Seed n2{"blake2b256", kDefaultKeyBits};
    itb::Seed d2{"blake2b256", kDefaultKeyBits};
    itb::Seed s2{"blake2b256", kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {}
    REQUIRE_FALSE(recovered);
}

TEST_CASE("blake2b256 seed invariants", "[blake2b][blake2b256][invariants]") {
    itb::Seed n{"blake2b256", kDefaultKeyBits};
    REQUIRE(n.width() == 256);
    REQUIRE(n.hash_name() == "blake2b256");
    REQUIRE(n.hash_key().size() == 32u);
}

// ---- blake2b512 (width 512) --------------------------------------

TEST_CASE("blake2b512 single ouroboros round-trip", "[blake2b][blake2b512][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_single_roundtrip("blake2b512", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("blake2b512 triple ouroboros round-trip", "[blake2b][blake2b512][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_triple_roundtrip("blake2b512", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("blake2b512 alternate key_bits round-trip", "[blake2b][blake2b512][altkb]") {
    // 2048 % 512 == 0
    SECTION("single 2048-bit") {
        run_single_roundtrip("blake2b512", kMaxKeyBits, 2048);
    }
    SECTION("triple 2048-bit") {
        run_triple_roundtrip("blake2b512", kMaxKeyBits, 2048);
    }
}

TEST_CASE("blake2b512 auth round-trip across MACs", "[blake2b][blake2b512][auth]") {
    for (const char* mac_name : kMacs) {
        SECTION(std::string{"mac="} + mac_name) {
            run_auth_roundtrip("blake2b512", kDefaultKeyBits, mac_name);
        }
    }
}

TEST_CASE("blake2b512 cross-seed decrypt does not recover plaintext",
          "[blake2b][blake2b512][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{"blake2b512", kDefaultKeyBits};
    itb::Seed d{"blake2b512", kDefaultKeyBits};
    itb::Seed s{"blake2b512", kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // The unauthenticated low-level decrypt may surface an ItbError or
    // return garbage that survived the structural checks; either is
    // acceptable. Recovering the original plaintext is forbidden.
    itb::Seed n2{"blake2b512", kDefaultKeyBits};
    itb::Seed d2{"blake2b512", kDefaultKeyBits};
    itb::Seed s2{"blake2b512", kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {}
    REQUIRE_FALSE(recovered);
}

TEST_CASE("blake2b512 seed invariants", "[blake2b][blake2b512][invariants]") {
    itb::Seed n{"blake2b512", kDefaultKeyBits};
    REQUIRE(n.width() == 512);
    REQUIRE(n.hash_name() == "blake2b512");
    REQUIRE(n.hash_key().size() == 64u);
}
