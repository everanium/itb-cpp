// test_nonce_sizes.cpp — round-trip tests across all nonce-size
// configurations (low-level free-function path).
//
// Mirrors bindings/c/tests/test_nonce_sizes.c. ITB exposes a runtime-
// configurable nonce size (itb::set_nonce_bits) that takes one of
// {128, 256, 512}. The on-the-wire chunk header therefore varies
// between 20, 36, and 68 bytes; every consumer that walks ciphertext
// on the byte level (chunk parsers, tampering tests, streaming
// decoders) must use itb::header_size() rather than a hardcoded
// constant.
//
// Per-binary process isolation (each test_*.cpp is its own binary)
// gives this file a fresh libitb global state. Each test case still
// saves and restores the active nonce_bits via an RAII guard so the
// suite remains deterministic regardless of test ordering.

#include <catch2/catch_test_macros.hpp>

#include <itb.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr std::array<int, 3> kNonceSizes{128, 256, 512};
constexpr std::array<const char*, 3> kHashes{"siphash24", "blake3", "blake2b512"};
constexpr std::array<const char*, 3> kMacNames{
    "kmac256", "hmac-sha256", "hmac-blake3"};

constexpr std::array<std::uint8_t, 32> kMacKey{
    0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
    0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
    0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
    0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
};

// RAII guard: snapshots the active nonce-bits at construction and
// restores it on destruction so each test case leaves the global
// state as it found it (defence against catch2 abort mid-test).
struct NonceBitsGuard {
    int saved;
    NonceBitsGuard() : saved{itb::get_nonce_bits()} {}
    ~NonceBitsGuard() noexcept {
        try { itb::set_nonce_bits(saved); } catch (...) {}
    }
    NonceBitsGuard(const NonceBitsGuard&) = delete;
    NonceBitsGuard& operator=(const NonceBitsGuard&) = delete;
};

std::vector<std::uint8_t> pseudo_plaintext(std::size_t n) {
    std::vector<std::uint8_t> p(n);
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = static_cast<std::uint8_t>(((i * 31u) + 7u) & 0xffu);
    }
    return p;
}

} // namespace

TEST_CASE("nonce_bits=128 yields 20-byte chunk header", "[nonce_sizes]") {
    NonceBitsGuard guard;
    REQUIRE_NOTHROW(itb::set_nonce_bits(128));
    REQUIRE(itb::header_size() == 20);
    REQUIRE(itb::get_nonce_bits() == 128);
}

TEST_CASE("header_size tracks nonce_bits dynamically", "[nonce_sizes]") {
    NonceBitsGuard guard;
    for (int bits : kNonceSizes) {
        REQUIRE_NOTHROW(itb::set_nonce_bits(bits));
        REQUIRE(itb::header_size() == bits / 8 + 4);
    }
}

TEST_CASE("encrypt + decrypt across nonce sizes (Single)",
          "[nonce_sizes]") {
    NonceBitsGuard guard;
    constexpr std::size_t pt_len = 1024;
    auto plaintext = pseudo_plaintext(pt_len);

    for (int bits : kNonceSizes) {
        REQUIRE_NOTHROW(itb::set_nonce_bits(bits));
        for (const char* hash : kHashes) {
            DYNAMIC_SECTION("hash=" << hash << " nonce_bits=" << bits) {
                itb::Seed n{hash, 1024};
                itb::Seed d{hash, 1024};
                itb::Seed s{hash, 1024};
                auto ct = itb::encrypt(n, d, s, plaintext);
                auto pt = itb::decrypt(n, d, s, ct);
                REQUIRE(pt == plaintext);

                // parse_chunk_len reports the full chunk length on the wire.
                auto hsize = static_cast<std::size_t>(itb::header_size());
                std::size_t chunk_len = 0;
                REQUIRE_NOTHROW(chunk_len = itb::parse_chunk_len(
                    ct.data(), hsize));
                REQUIRE(chunk_len == ct.size());
            }
        }
    }
}

TEST_CASE("encrypt_triple + decrypt_triple across nonce sizes",
          "[nonce_sizes]") {
    NonceBitsGuard guard;
    constexpr std::size_t pt_len = 1024;
    auto plaintext = pseudo_plaintext(pt_len);

    for (int bits : kNonceSizes) {
        REQUIRE_NOTHROW(itb::set_nonce_bits(bits));
        for (const char* hash : kHashes) {
            DYNAMIC_SECTION("hash=" << hash << " nonce_bits=" << bits) {
                std::vector<itb::Seed> seeds;
                seeds.reserve(7);
                for (int k = 0; k < 7; ++k) {
                    seeds.emplace_back(hash, 1024);
                }
                auto ct = itb::encrypt_triple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], plaintext);
                auto pt = itb::decrypt_triple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], ct);
                REQUIRE(pt == plaintext);
            }
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth across nonce sizes (Single)",
          "[nonce_sizes]") {
    NonceBitsGuard guard;
    constexpr std::size_t pt_len = 1024;
    auto plaintext = pseudo_plaintext(pt_len);
    std::vector<std::uint8_t> mac_key(kMacKey.begin(), kMacKey.end());

    for (int bits : kNonceSizes) {
        REQUIRE_NOTHROW(itb::set_nonce_bits(bits));
        for (const char* mac_name : kMacNames) {
            DYNAMIC_SECTION("mac=" << mac_name << " nonce_bits=" << bits) {
                itb::Mac mac{mac_name, mac_key};
                itb::Seed n{"blake3", 1024};
                itb::Seed d{"blake3", 1024};
                itb::Seed s{"blake3", 1024};

                auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
                auto pt = itb::decrypt_auth(n, d, s, mac, ct);
                REQUIRE(pt == plaintext);

                // Tamper: flip a few bytes in the body window past the
                // header, expect MAC_FAILURE on decrypt.
                auto hsize = static_cast<std::size_t>(itb::header_size());
                std::size_t end = hsize + 256;
                if (end > ct.size()) {
                    end = ct.size();
                }
                for (std::size_t b = hsize; b < end; ++b) {
                    ct[b] ^= 0x01;
                }
                REQUIRE_THROWS_AS(
                    itb::decrypt_auth(n, d, s, mac, ct),
                    itb::ItbError);
            }
        }
    }
}

TEST_CASE("encrypt_auth_triple + decrypt_auth_triple across nonce sizes",
          "[nonce_sizes]") {
    NonceBitsGuard guard;
    constexpr std::size_t pt_len = 1024;
    auto plaintext = pseudo_plaintext(pt_len);
    std::vector<std::uint8_t> mac_key(kMacKey.begin(), kMacKey.end());

    for (int bits : kNonceSizes) {
        REQUIRE_NOTHROW(itb::set_nonce_bits(bits));
        for (const char* mac_name : kMacNames) {
            DYNAMIC_SECTION("mac=" << mac_name << " nonce_bits=" << bits) {
                itb::Mac mac{mac_name, mac_key};
                std::vector<itb::Seed> seeds;
                seeds.reserve(7);
                for (int k = 0; k < 7; ++k) {
                    seeds.emplace_back("blake3", 1024);
                }
                auto ct = itb::encrypt_auth_triple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], mac, plaintext);
                auto pt = itb::decrypt_auth_triple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], mac, ct);
                REQUIRE(pt == plaintext);

                auto hsize = static_cast<std::size_t>(itb::header_size());
                std::size_t end = hsize + 256;
                if (end > ct.size()) {
                    end = ct.size();
                }
                for (std::size_t b = hsize; b < end; ++b) {
                    ct[b] ^= 0x01;
                }
                REQUIRE_THROWS_AS(
                    itb::decrypt_auth_triple(seeds[0], seeds[1], seeds[2],
                                             seeds[3], seeds[4], seeds[5],
                                             seeds[6], mac, ct),
                    itb::ItbError);
            }
        }
    }
}
