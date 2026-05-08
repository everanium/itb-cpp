// test_empty_payload.cpp — empty plaintext / ciphertext rejection.
//
// libitb refuses empty payloads on every cipher entry point ("itb:
// empty data"). The C++ binding does not short-circuit — it forwards
// the empty buffer pointer / length to the C ABI and surfaces whatever
// status libitb reports as ItbError. Asserts the rejection happens
// (not the precise status code, which is implementation-defined).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;
constexpr const char* kMac  = "hmac-blake3";

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

template <class Fn>
void expect_thrown_non_ok(Fn&& callable) {
    try {
        callable();
        FAIL("expected ItbError on empty payload");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() != itb::status::kOk);
    }
}

const std::vector<std::uint8_t> kEmptyVec{};
constexpr std::string_view      kEmptySv{""};

} // namespace

TEST_CASE("Encryptor::encrypt rejects empty plaintext (single)",
          "[empty][encryptor][single]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    SECTION("vector overload") {
        expect_thrown_non_ok([&]{ enc.encrypt(kEmptyVec); });
    }
    SECTION("string_view overload") {
        expect_thrown_non_ok([&]{ enc.encrypt(kEmptySv); });
    }
    SECTION("ptr/len overload (nullptr, 0)") {
        expect_thrown_non_ok([&]{ enc.encrypt(nullptr, 0); });
    }
}

TEST_CASE("Encryptor::encrypt_auth rejects empty plaintext (single)",
          "[empty][encryptor][single][auth]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    SECTION("vector overload") {
        expect_thrown_non_ok([&]{ enc.encrypt_auth(kEmptyVec); });
    }
    SECTION("string_view overload") {
        expect_thrown_non_ok([&]{ enc.encrypt_auth(kEmptySv); });
    }
}

TEST_CASE("Encryptor::decrypt rejects empty ciphertext (single)",
          "[empty][encryptor][single]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    SECTION("vector overload") {
        expect_thrown_non_ok([&]{ enc.decrypt(kEmptyVec); });
    }
    SECTION("string_view overload") {
        expect_thrown_non_ok([&]{ enc.decrypt(kEmptySv); });
    }
}

TEST_CASE("Encryptor::decrypt_auth rejects empty ciphertext (single)",
          "[empty][encryptor][single][auth]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    SECTION("vector overload") {
        expect_thrown_non_ok([&]{ enc.decrypt_auth(kEmptyVec); });
    }
    SECTION("string_view overload") {
        expect_thrown_non_ok([&]{ enc.decrypt_auth(kEmptySv); });
    }
}

TEST_CASE("Encryptor cipher entry points reject empty (triple)",
          "[empty][encryptor][triple]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 3};
    SECTION("encrypt") {
        expect_thrown_non_ok([&]{ enc.encrypt(kEmptyVec); });
    }
    SECTION("decrypt") {
        expect_thrown_non_ok([&]{ enc.decrypt(kEmptyVec); });
    }
    SECTION("encrypt_auth") {
        expect_thrown_non_ok([&]{ enc.encrypt_auth(kEmptyVec); });
    }
    SECTION("decrypt_auth") {
        expect_thrown_non_ok([&]{ enc.decrypt_auth(kEmptyVec); });
    }
}

TEST_CASE("itb::encrypt free function rejects empty plaintext (single)",
          "[empty][free][single]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    SECTION("vector overload") {
        expect_thrown_non_ok([&]{
            (void)itb::encrypt(noise, data, start, kEmptyVec);
        });
    }
    SECTION("string_view overload") {
        expect_thrown_non_ok([&]{
            (void)itb::encrypt(noise, data, start, kEmptySv);
        });
    }
    SECTION("ptr/len overload (nullptr, 0)") {
        expect_thrown_non_ok([&]{
            (void)itb::encrypt(noise, data, start,
                               static_cast<const std::uint8_t*>(nullptr), 0);
        });
    }
}

TEST_CASE("itb::decrypt free function rejects empty ciphertext (single)",
          "[empty][free][single]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    expect_thrown_non_ok([&]{
        (void)itb::decrypt(noise, data, start, kEmptyVec);
    });
}

TEST_CASE("itb::encrypt_triple free function rejects empty plaintext",
          "[empty][free][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    expect_thrown_non_ok([&]{
        (void)itb::encrypt_triple(noise, d1, d2, d3, s1, s2, s3, kEmptyVec);
    });
}

TEST_CASE("itb::decrypt_triple free function rejects empty ciphertext",
          "[empty][free][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    expect_thrown_non_ok([&]{
        (void)itb::decrypt_triple(noise, d1, d2, d3, s1, s2, s3, kEmptyVec);
    });
}
