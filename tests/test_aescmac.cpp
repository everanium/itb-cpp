// test_aescmac.cpp — AES-CMAC-focused low-level cipher coverage.
//
// Mirrors bindings/c/tests/test_aescmac.c on the C++ free-function
// cipher surface (`itb::Seed` + `itb::encrypt` / `itb::decrypt` and
// the Triple counterparts), without mutating the process-wide
// nonce_bits state. AES-CMAC ships at a single native width (128 —
// the AES block size), so the per-primitive sweep covers the single
// hash entry across the canonical 1024-bit key and the maximal
// 2048-bit key (both multiples of 128).

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
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr const char* kPrimitive = "aescmac";
constexpr int kAescmacWidth      = 128;
constexpr int kDefaultKeyBits    = 1024;
// 2048 % 128 == 0 — the largest libitb-supported alternate width
// divisible by the AES-CMAC block size.
constexpr int kAltKeyBits        = 2048;

constexpr const char* kMacs[] = {"kmac256", "hmac-sha256", "hmac-blake3"};

const std::size_t kSizes[] = {32u, 4096u, 65536u};

} // namespace

TEST_CASE("aescmac single ouroboros round-trip", "[aescmac][single]") {
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

TEST_CASE("aescmac triple ouroboros round-trip", "[aescmac][triple]") {
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

TEST_CASE("aescmac alternate key_bits round-trip", "[aescmac][altkb]") {
    auto plaintext = token_bytes(2048);

    SECTION("single 2048-bit") {
        itb::Seed n{kPrimitive, kAltKeyBits};
        itb::Seed d{kPrimitive, kAltKeyBits};
        itb::Seed s{kPrimitive, kAltKeyBits};
        REQUIRE(n.width() == kAescmacWidth);
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

TEST_CASE("aescmac auth round-trip across MACs", "[aescmac][auth]") {
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

            // Tamper at the dynamic header offset — flip a 256-byte
            // window so the MAC catches the change deterministically.
            int hsize = itb::header_size();
            REQUIRE(hsize > 0);
            REQUIRE(static_cast<std::size_t>(hsize) < ct.size());
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

TEST_CASE("aescmac cross-seed decrypt does not recover plaintext",
          "[aescmac][cross]") {
    auto plaintext = token_bytes(512);
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    itb::Seed d{kPrimitive, kDefaultKeyBits};
    itb::Seed s{kPrimitive, kDefaultKeyBits};
    auto ct = itb::encrypt(n, d, s, plaintext);

    // Different fresh seeds — the unauthenticated low-level decrypt has
    // no integrity tag, so the call may either surface an ItbError
    // (typical) or return garbage bytes that survived the COBS /
    // header structural checks. Both outcomes are correct; what is
    // forbidden is recovering the original plaintext.
    itb::Seed n2{kPrimitive, kDefaultKeyBits};
    itb::Seed d2{kPrimitive, kDefaultKeyBits};
    itb::Seed s2{kPrimitive, kDefaultKeyBits};
    bool recovered = false;
    try {
        auto pt = itb::decrypt(n2, d2, s2, ct);
        recovered = (pt == plaintext);
    } catch (const itb::ItbError&) {
        // Acceptable: structural rejection caught the wrong seeds.
    }
    REQUIRE_FALSE(recovered);
}

TEST_CASE("aescmac seed invariants", "[aescmac][invariants]") {
    itb::Seed n{kPrimitive, kDefaultKeyBits};
    REQUIRE(n.width() == kAescmacWidth);
    REQUIRE(n.hash_name() == kPrimitive);
    // AES-CMAC ships with an internal fixed AES-128 key — the
    // hash_key accessor returns exactly 16 bytes.
    REQUIRE(n.hash_key().size() == 16u);
    // 1024-bit key feeds 16 uint64 components.
    REQUIRE(n.components().size() == static_cast<std::size_t>(kDefaultKeyBits / 64));
}
