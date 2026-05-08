// test_nonce_sizes.cpp — per-instance Encryptor::set_nonce_bits
// coverage.
//
// Encryptor::set_nonce_bits flips a per-instance atomic on the C
// binding side; the encryptor's nonce_bits / header_size / parse_chunk_len
// accessors track the override without touching the process-global
// itb::set_nonce_bits / itb::get_nonce_bits surface. None of the
// SECTIONs here mutate process-global state — that is reserved for
// test_streams_nonce.cpp's dedicated process.
//
// Mirrors bindings/c/tests/test_easy_nonce_sizes.c on the C++ surface.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;
constexpr const char* kMac  = "hmac-blake3";

const int kNonceBits[] = {128, 256, 512};

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0x0123456789ABCDEFULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

} // namespace

TEST_CASE("default nonce_bits is 128 and header_size is 20",
          "[nonce_sizes][default]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    REQUIRE(enc.nonce_bits() == 128);
    REQUIRE(enc.header_size() == 20); // 128/8 + 4
}

TEST_CASE("set_nonce_bits adjusts header_size accordingly",
          "[nonce_sizes][header_size]") {
    for (int nb : kNonceBits) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{kPrim, kKb, kMac, 1};
            enc.set_nonce_bits(nb);
            REQUIRE(enc.nonce_bits() == nb);
            REQUIRE(enc.header_size() == nb / 8 + 4);
        }
    }
}

TEST_CASE("encrypt + decrypt round-trips at every nonce_bits (single)",
          "[nonce_sizes][single]") {
    auto pt = token_bytes(1024);
    for (int nb : kNonceBits) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{kPrim, kKb, kMac, 1};
            enc.set_nonce_bits(nb);
            auto ct = enc.encrypt(pt);
            REQUIRE(enc.decrypt(ct) == pt);
            // parse_chunk_len reports the full ciphertext length.
            int hs = enc.header_size();
            std::vector<std::uint8_t> hdr(ct.begin(),
                                          ct.begin() + hs);
            REQUIRE(enc.parse_chunk_len(hdr) == ct.size());
        }
    }
}

TEST_CASE("encrypt + decrypt round-trips at every nonce_bits (triple)",
          "[nonce_sizes][triple]") {
    auto pt = token_bytes(1024);
    for (int nb : kNonceBits) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{kPrim, kKb, kMac, 3};
            enc.set_nonce_bits(nb);
            auto ct = enc.encrypt(pt);
            REQUIRE(enc.decrypt(ct) == pt);
        }
    }
}

TEST_CASE("encrypt_auth + decrypt_auth round-trips at every nonce_bits",
          "[nonce_sizes][auth]") {
    auto pt = token_bytes(1024);
    for (int nb : kNonceBits) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{kPrim, kKb, kMac, 1};
            enc.set_nonce_bits(nb);
            auto ct = enc.encrypt_auth(pt);
            REQUIRE(enc.decrypt_auth(ct) == pt);
        }
    }
}

TEST_CASE("two encryptors hold independent nonce_bits values",
          "[nonce_sizes][isolation]") {
    itb::Encryptor a{kPrim, kKb, kMac, 1};
    itb::Encryptor b{kPrim, kKb, kMac, 1};

    a.set_nonce_bits(512);
    REQUIRE(a.nonce_bits() == 512);
    REQUIRE(a.header_size() == 68); // 512/8 + 4

    REQUIRE(b.nonce_bits() == 128);
    REQUIRE(b.header_size() == 20);
}

TEST_CASE("cross-encryptor decrypt at matching nonce_bits via export/import",
          "[nonce_sizes][persistence]") {
    auto pt = token_bytes(2048);
    itb::Encryptor src{kPrim, kKb, kMac, 1};
    src.set_nonce_bits(256);
    auto blob = src.export_state();
    auto ct   = src.encrypt(pt);

    itb::Encryptor dst{kPrim, kKb, kMac, 1};
    dst.import_state(blob);
    dst.set_nonce_bits(256);
    REQUIRE(dst.nonce_bits() == 256);
    REQUIRE(dst.decrypt(ct) == pt);
}

TEST_CASE("nonce_bits override survives export + import round-trip",
          "[nonce_sizes][persistence]") {
    auto pt = token_bytes(1024);
    itb::Encryptor src{kPrim, kKb, kMac, 1};
    src.set_nonce_bits(256);
    auto blob = src.export_state();
    auto ct   = src.encrypt(pt);

    itb::Encryptor dst{kPrim, kKb, kMac, 1};
    dst.import_state(blob);
    // The per-instance nonce_bits override is part of the persisted
    // state and is restored by import_state — the receiving encryptor
    // therefore decodes correctly without the caller having to call
    // set_nonce_bits a second time on it.
    REQUIRE(dst.nonce_bits() == 256);
    REQUIRE(dst.decrypt(ct) == pt);
}
