// test_areion.cpp — Areion-SoEM-{256,512} low-level cipher coverage.
//
// Mirrors bindings/c/tests/test_areion.c on the C++ free-function
// cipher surface. Areion-SoEM ships at two native widths (256 and
// 512); each is exercised in its own TEST_CASE block.

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

// ---- areion256 (width 256) ---------------------------------------

TEST_CASE("areion256 single ouroboros round-trip", "[areion][areion256][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_single_roundtrip("areion256", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("areion256 triple ouroboros round-trip", "[areion][areion256][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_triple_roundtrip("areion256", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("areion256 alternate key_bits round-trip", "[areion][areion256][altkb]") {
    // 2048 % 256 == 0
    SECTION("single 2048-bit") {
        run_single_roundtrip("areion256", kMaxKeyBits, 2048);
    }
    SECTION("triple 2048-bit") {
        run_triple_roundtrip("areion256", kMaxKeyBits, 2048);
    }
}

TEST_CASE("areion256 auth round-trip across MACs", "[areion][areion256][auth]") {
    for (const char* mac_name : kMacs) {
        SECTION(std::string{"mac="} + mac_name) {
            run_auth_roundtrip("areion256", kDefaultKeyBits, mac_name);
        }
    }
}

TEST_CASE("areion256 cross-seed decrypt does not recover plaintext",
          "[areion][areion256][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{"areion256", kDefaultKeyBits};
    itb::Seed d{"areion256", kDefaultKeyBits};
    itb::Seed s{"areion256", kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // The unauthenticated low-level decrypt may surface an ItbError or
    // return garbage that survived the structural checks; either is
    // acceptable. Recovering the original plaintext is forbidden.
    itb::Seed n2{"areion256", kDefaultKeyBits};
    itb::Seed d2{"areion256", kDefaultKeyBits};
    itb::Seed s2{"areion256", kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {}
    REQUIRE_FALSE(recovered);
}

TEST_CASE("areion256 seed invariants", "[areion][areion256][invariants]") {
    itb::Seed n{"areion256", kDefaultKeyBits};
    REQUIRE(n.width() == 256);
    REQUIRE(n.hash_name() == "areion256");
    REQUIRE(n.hash_key().size() == 32u);
}

// ---- areion512 (width 512) ---------------------------------------

TEST_CASE("areion512 single ouroboros round-trip", "[areion][areion512][single]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_single_roundtrip("areion512", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("areion512 triple ouroboros round-trip", "[areion][areion512][triple]") {
    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            run_triple_roundtrip("areion512", kDefaultKeyBits, sz);
        }
    }
}

TEST_CASE("areion512 alternate key_bits round-trip", "[areion][areion512][altkb]") {
    // 2048 % 512 == 0
    SECTION("single 2048-bit") {
        run_single_roundtrip("areion512", kMaxKeyBits, 2048);
    }
    SECTION("triple 2048-bit") {
        run_triple_roundtrip("areion512", kMaxKeyBits, 2048);
    }
}

TEST_CASE("areion512 auth round-trip across MACs", "[areion][areion512][auth]") {
    for (const char* mac_name : kMacs) {
        SECTION(std::string{"mac="} + mac_name) {
            run_auth_roundtrip("areion512", kDefaultKeyBits, mac_name);
        }
    }
}

TEST_CASE("areion512 cross-seed decrypt does not recover plaintext",
          "[areion][areion512][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{"areion512", kDefaultKeyBits};
    itb::Seed d{"areion512", kDefaultKeyBits};
    itb::Seed s{"areion512", kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // The unauthenticated low-level decrypt may surface an ItbError or
    // return garbage that survived the structural checks; either is
    // acceptable. Recovering the original plaintext is forbidden.
    itb::Seed n2{"areion512", kDefaultKeyBits};
    itb::Seed d2{"areion512", kDefaultKeyBits};
    itb::Seed s2{"areion512", kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {}
    REQUIRE_FALSE(recovered);
}

TEST_CASE("areion512 seed invariants", "[areion][areion512][invariants]") {
    itb::Seed n{"areion512", kDefaultKeyBits};
    REQUIRE(n.width() == 512);
    REQUIRE(n.hash_name() == "areion512");
    REQUIRE(n.hash_key().size() == 64u);
}
