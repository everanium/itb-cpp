// test_roundtrip.cpp — generic Seed / MAC / cipher round-trip coverage.
//
// Mirrors bindings/c/tests/test_roundtrip.c on the C++ free-function
// cipher surface. Confirms the Seed, MAC, and low-level encrypt /
// decrypt entry points round-trip plaintext correctly across every
// primitive in the canonical FFI registry × the three ITB key-bit
// widths (512 / 1024 / 2048) that are valid for each native hash
// width. Covers Single, Triple, and Authenticated variants plus the
// version / list_hashes / constants probes.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr const char kPlaintextBytes[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
constexpr std::size_t kPlaintextLen = sizeof(kPlaintextBytes) - 1;

std::vector<std::uint8_t> kPlaintext() {
    return std::vector<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(kPlaintextBytes),
        reinterpret_cast<const std::uint8_t*>(kPlaintextBytes) + kPlaintextLen);
}

struct CanonicalHash {
    const char* name;
    int width;
};

constexpr CanonicalHash kCanonicalHashes[] = {
    {"areion256",  256},
    {"areion512",  512},
    {"siphash24",  128},
    {"aescmac",    128},
    {"blake2b256", 256},
    {"blake2b512", 512},
    {"blake2s",    256},
    {"blake3",     256},
    {"chacha20",   256},
};

constexpr int kKeyBits[] = {512, 1024, 2048};

std::vector<std::uint8_t> pseudo_payload(std::size_t n) {
    std::vector<std::uint8_t> p(n);
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = static_cast<std::uint8_t>(((i * 17u) + 5u) & 0xffu);
    }
    return p;
}

} // namespace

TEST_CASE("roundtrip single blake3 baseline", "[roundtrip][single][blake3]") {
    auto plaintext = kPlaintext();
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    auto ct = itb::encrypt(n, d, s, plaintext);
    // ITB containerises plaintext into a larger pixel grid — ciphertext
    // length must exceed the plaintext length.
    REQUIRE(ct.size() > plaintext.size());

    auto pt = itb::decrypt(n, d, s, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("roundtrip triple blake3 baseline", "[roundtrip][triple][blake3]") {
    auto plaintext = kPlaintext();
    itb::Seed n {"blake3", 1024};
    itb::Seed d1{"blake3", 1024};
    itb::Seed d2{"blake3", 1024};
    itb::Seed d3{"blake3", 1024};
    itb::Seed s1{"blake3", 1024};
    itb::Seed s2{"blake3", 1024};
    itb::Seed s3{"blake3", 1024};

    auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3, plaintext);
    auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("roundtrip auth single hmac-sha256",
          "[roundtrip][auth][hmac_sha256]") {
    auto plaintext = kPlaintext();
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    std::vector<std::uint8_t> key(32, 0x42);
    itb::Mac mac{"hmac-sha256", key};

    auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
    auto pt = itb::decrypt_auth(n, d, s, mac, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("roundtrip auth triple kmac256",
          "[roundtrip][auth][triple][kmac256]") {
    auto plaintext = kPlaintext();
    itb::Seed n {"blake3", 1024};
    itb::Seed d1{"blake3", 1024};
    itb::Seed d2{"blake3", 1024};
    itb::Seed d3{"blake3", 1024};
    itb::Seed s1{"blake3", 1024};
    itb::Seed s2{"blake3", 1024};
    itb::Seed s3{"blake3", 1024};

    std::vector<std::uint8_t> key(32, 0x21);
    itb::Mac mac{"kmac256", key};

    auto ct = itb::encrypt_auth_triple(n, d1, d2, d3, s1, s2, s3, mac,
                                       plaintext);
    auto pt = itb::decrypt_auth_triple(n, d1, d2, d3, s1, s2, s3, mac, ct);
    REQUIRE(pt == plaintext);
}

TEST_CASE("roundtrip seed components round-trip is identity",
          "[roundtrip][persistence][identity]") {
    itb::Seed s{"blake3", 1024};
    auto comps = s.components();
    auto key   = s.hash_key();

    auto s2 = itb::Seed::from_components("blake3", comps, key);
    auto comps2 = s2.components();
    auto key2   = s2.hash_key();

    REQUIRE(comps2 == comps);
    REQUIRE(key2   == key);
}

TEST_CASE("roundtrip auth tampered ciphertext fails MAC",
          "[roundtrip][auth][tamper]") {
    auto plaintext = kPlaintext();
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    std::vector<std::uint8_t> key(32, 0);
    itb::Mac mac{"hmac-sha256", key};

    auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
    REQUIRE(!ct.empty());
    ct.back() ^= 0xff;
    try {
        (void) itb::decrypt_auth(n, d, s, mac, ct);
        FAIL("expected MAC_FAILURE on tampered ciphertext");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kMacFailure);
    }
}

TEST_CASE("roundtrip seed construct + free does not crash",
          "[roundtrip][lifecycle]") {
    for (int i = 0; i < 32; ++i) {
        itb::Seed seed{"blake3", 512};
        REQUIRE(seed.width() == 256);
    }
}

TEST_CASE("roundtrip version reports SemVer-shaped string",
          "[roundtrip][version]") {
    auto v = itb::version();
    REQUIRE(!v.empty());
    auto first_dot = v.find('.');
    REQUIRE(first_dot != std::string::npos);
    auto second_dot = v.find('.', first_dot + 1);
    REQUIRE(second_dot != std::string::npos);
    for (std::size_t i = 0; i < first_dot; ++i) {
        REQUIRE(std::isdigit(static_cast<unsigned char>(v[i])));
    }
    for (std::size_t i = first_dot + 1; i < second_dot; ++i) {
        REQUIRE(std::isdigit(static_cast<unsigned char>(v[i])));
    }
    REQUIRE(std::isdigit(static_cast<unsigned char>(v[second_dot + 1])));
}

TEST_CASE("roundtrip list_hashes returns canonical 9-entry registry",
          "[roundtrip][registry]") {
    auto entries = itb::list_hashes();
    REQUIRE(entries.size() ==
            sizeof(kCanonicalHashes) / sizeof(kCanonicalHashes[0]));
    for (std::size_t i = 0; i < entries.size(); ++i) {
        REQUIRE(entries[i].name  == kCanonicalHashes[i].name);
        REQUIRE(entries[i].width == kCanonicalHashes[i].width);
    }
}

TEST_CASE("roundtrip library constants", "[roundtrip][constants]") {
    REQUIRE(itb::max_key_bits() == 2048);
    REQUIRE(itb::channels()     == 8);
    REQUIRE(itb::header_size()  >  0);
}

TEST_CASE("roundtrip Seed reports name + width", "[roundtrip][seed_meta]") {
    itb::Seed s{"blake3", 1024};
    REQUIRE(s.hash_name() == "blake3");
    REQUIRE(s.width()     == 256);
}

TEST_CASE("roundtrip Seed rejects unknown primitive", "[roundtrip][bad_hash]") {
    try {
        (void) itb::Seed{"nonsense-hash", 1024};
        FAIL("expected ItbError(BAD_HASH)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadHash);
    }
}

TEST_CASE("roundtrip Seed rejects bad key_bits", "[roundtrip][bad_key_bits]") {
    static const int kBad[] = {0, 256, 511, 2049};
    for (int kb : kBad) {
        SECTION(std::string{"key_bits="} + std::to_string(kb)) {
            try {
                (void) itb::Seed{"blake3", kb};
                FAIL("expected ItbError(BAD_KEY_BITS)");
            } catch (const itb::ItbError& e) {
                REQUIRE(e.code() == itb::status::kBadKeyBits);
            }
        }
    }
}

TEST_CASE("roundtrip every primitive every key_bits single",
          "[roundtrip][matrix][single]") {
    auto plaintext = pseudo_payload(4096);

    for (const auto& spec : kCanonicalHashes) {
        for (int kb : kKeyBits) {
            // Filter widths the primitive cannot satisfy (e.g. siphash24
            // 128 supports 512/1024/2048; areion512 needs kb % 512 == 0).
            if (kb % spec.width != 0) continue;
            SECTION(std::string{"hash="} + spec.name
                    + " key_bits=" + std::to_string(kb)) {
                itb::Seed n{spec.name, kb};
                itb::Seed d{spec.name, kb};
                itb::Seed s{spec.name, kb};
                auto ct = itb::encrypt(n, d, s, plaintext);
                REQUIRE(ct.size() > plaintext.size());
                auto pt = itb::decrypt(n, d, s, ct);
                REQUIRE(pt == plaintext);
            }
        }
    }
}

TEST_CASE("roundtrip every primitive every key_bits triple",
          "[roundtrip][matrix][triple]") {
    auto plaintext = pseudo_payload(4096);

    for (const auto& spec : kCanonicalHashes) {
        for (int kb : kKeyBits) {
            if (kb % spec.width != 0) continue;
            SECTION(std::string{"hash="} + spec.name
                    + " key_bits=" + std::to_string(kb)) {
                itb::Seed n {spec.name, kb};
                itb::Seed d1{spec.name, kb};
                itb::Seed d2{spec.name, kb};
                itb::Seed d3{spec.name, kb};
                itb::Seed s1{spec.name, kb};
                itb::Seed s2{spec.name, kb};
                itb::Seed s3{spec.name, kb};
                auto ct = itb::encrypt_triple(n, d1, d2, d3, s1, s2, s3,
                                              plaintext);
                REQUIRE(ct.size() > plaintext.size());
                auto pt = itb::decrypt_triple(n, d1, d2, d3, s1, s2, s3, ct);
                REQUIRE(pt == plaintext);
            }
        }
    }
}

TEST_CASE("roundtrip seed width mismatch surfaces SEED_WIDTH_MIX",
          "[roundtrip][width_mismatch]") {
    itb::Seed n{"siphash24", 1024}; // width 128
    itb::Seed d{"blake3",    1024}; // width 256
    itb::Seed s{"blake3",    1024}; // width 256

    static const std::uint8_t pt_bytes[] = "hello";
    std::vector<std::uint8_t> plaintext(pt_bytes, pt_bytes + sizeof(pt_bytes) - 1);
    try {
        (void) itb::encrypt(n, d, s, plaintext);
        FAIL("expected ItbError(SEED_WIDTH_MIX)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kSeedWidthMix);
    }
}

TEST_CASE("roundtrip triple seed width mismatch surfaces SEED_WIDTH_MIX",
          "[roundtrip][triple][width_mismatch]") {
    itb::Seed odd{"siphash24", 1024}; // width 128
    itb::Seed r0{"blake3", 1024};
    itb::Seed r1{"blake3", 1024};
    itb::Seed r2{"blake3", 1024};
    itb::Seed r3{"blake3", 1024};
    itb::Seed r4{"blake3", 1024};
    itb::Seed r5{"blake3", 1024};

    static const std::uint8_t pt_bytes[] = "hello";
    std::vector<std::uint8_t> plaintext(pt_bytes, pt_bytes + sizeof(pt_bytes) - 1);
    try {
        (void) itb::encrypt_triple(odd, r0, r1, r2, r3, r4, r5, plaintext);
        FAIL("expected ItbError(SEED_WIDTH_MIX)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kSeedWidthMix);
    }
}

TEST_CASE("roundtrip across boundary payload sizes",
          "[roundtrip][sizes]") {
    static const std::size_t kSizes[] = {1u, 17u, 4096u, 65536u};
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    for (std::size_t sz : kSizes) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            auto plaintext = pseudo_payload(sz);
            auto ct = itb::encrypt(n, d, s, plaintext);
            auto pt = itb::decrypt(n, d, s, ct);
            REQUIRE(pt == plaintext);
        }
    }
}
