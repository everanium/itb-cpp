// test_auth.cpp — end-to-end authenticated-encryption coverage for the
// C++ binding's low-level surface.
//
// Mirrors bindings/c/tests/test_auth.c. Exercises the 3 MACs × 3 hash
// widths × {Single, Triple} round-trip plus tamper rejection at the
// dynamic header offset and cross-MAC rejection (different primitive
// or same primitive with a different key).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct CanonicalMac {
    const char* name;
    int key_size;
    int tag_size;
    int min_key_bytes;
};

constexpr CanonicalMac kCanonicalMacs[] = {
    {"kmac256",     32, 32, 16},
    {"hmac-sha256", 32, 32, 16},
    {"hmac-blake3", 32, 32, 32},
};

// One representative hash per ITB key-width axis (128 / 256 / 512).
struct HashByWidth {
    const char* name;
    int width;
};

constexpr HashByWidth kHashByWidth[] = {
    {"siphash24",  128},
    {"blake3",     256},
    {"blake2b512", 512},
};

const std::vector<std::uint8_t> kKeyBytes(32, 0x42);

std::vector<std::uint8_t> pseudo_plaintext(std::size_t n) {
    std::vector<std::uint8_t> p(n);
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = static_cast<std::uint8_t>(i & 0xffu);
    }
    return p;
}

} // namespace

TEST_CASE("auth list_macs returns the canonical 3-entry registry",
          "[auth][registry]") {
    auto entries = itb::list_macs();
    REQUIRE(entries.size() == sizeof(kCanonicalMacs) / sizeof(kCanonicalMacs[0]));
    for (std::size_t i = 0; i < entries.size(); ++i) {
        REQUIRE(entries[i].name          == kCanonicalMacs[i].name);
        REQUIRE(entries[i].key_size      == kCanonicalMacs[i].key_size);
        REQUIRE(entries[i].tag_size      == kCanonicalMacs[i].tag_size);
        REQUIRE(entries[i].min_key_bytes == kCanonicalMacs[i].min_key_bytes);
    }
}

TEST_CASE("auth Mac construct + free for every primitive",
          "[auth][construct]") {
    for (const auto& spec : kCanonicalMacs) {
        SECTION(std::string{"primitive="} + spec.name) {
            REQUIRE_NOTHROW(itb::Mac{spec.name, kKeyBytes});
        }
    }
}

TEST_CASE("auth Mac repeated construct/free does not leak",
          "[auth][lifecycle]") {
    for (int i = 0; i < 32; ++i) {
        itb::Mac m{"hmac-sha256", kKeyBytes};
        (void) m.name();
    }
}

TEST_CASE("auth Mac rejects unknown primitive", "[auth][bad_name]") {
    try {
        (void) itb::Mac{"nonsense-mac", kKeyBytes};
        FAIL("expected ItbError(BAD_MAC) for unknown primitive");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadMac);
    }
}

TEST_CASE("auth Mac rejects short keys", "[auth][short_key]") {
    for (const auto& spec : kCanonicalMacs) {
        SECTION(std::string{"primitive="} + spec.name) {
            std::size_t short_len =
                static_cast<std::size_t>(spec.min_key_bytes - 1);
            std::vector<std::uint8_t> short_key(short_len, 0x11);
            try {
                (void) itb::Mac{spec.name, short_key};
                FAIL("expected ItbError(BAD_INPUT) for short key");
            } catch (const itb::ItbError& e) {
                REQUIRE(e.code() == itb::status::kBadInput);
            }
        }
    }
}

TEST_CASE("auth single round-trip across MACs and hash widths",
          "[auth][single][matrix]") {
    auto plaintext = pseudo_plaintext(4096);

    for (const auto& mac_spec : kCanonicalMacs) {
        for (const auto& hash_spec : kHashByWidth) {
            SECTION(std::string{"mac="} + mac_spec.name
                    + " hash=" + hash_spec.name) {
                itb::Mac mac{mac_spec.name, kKeyBytes};
                itb::Seed n{hash_spec.name, 1024};
                itb::Seed d{hash_spec.name, 1024};
                itb::Seed s{hash_spec.name, 1024};

                auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
                auto pt = itb::decrypt_auth(n, d, s, mac, ct);
                REQUIRE(pt == plaintext);

                int hsize = itb::header_size();
                REQUIRE(hsize > 0);
                std::size_t end = static_cast<std::size_t>(hsize) + 256;
                if (end > ct.size()) end = ct.size();
                for (std::size_t b = static_cast<std::size_t>(hsize);
                     b < end; ++b) {
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
}

TEST_CASE("auth triple round-trip across MACs and hash widths",
          "[auth][triple][matrix]") {
    auto plaintext = pseudo_plaintext(4096);

    for (const auto& mac_spec : kCanonicalMacs) {
        for (const auto& hash_spec : kHashByWidth) {
            SECTION(std::string{"mac="} + mac_spec.name
                    + " hash=" + hash_spec.name) {
                itb::Mac mac{mac_spec.name, kKeyBytes};
                itb::Seed n {hash_spec.name, 1024};
                itb::Seed d1{hash_spec.name, 1024};
                itb::Seed d2{hash_spec.name, 1024};
                itb::Seed d3{hash_spec.name, 1024};
                itb::Seed s1{hash_spec.name, 1024};
                itb::Seed s2{hash_spec.name, 1024};
                itb::Seed s3{hash_spec.name, 1024};

                auto ct = itb::encrypt_auth_triple(n, d1, d2, d3,
                                                   s1, s2, s3, mac,
                                                   plaintext);
                auto pt = itb::decrypt_auth_triple(n, d1, d2, d3,
                                                   s1, s2, s3, mac, ct);
                REQUIRE(pt == plaintext);

                int hsize = itb::header_size();
                REQUIRE(hsize > 0);
                std::size_t end = static_cast<std::size_t>(hsize) + 256;
                if (end > ct.size()) end = ct.size();
                for (std::size_t b = static_cast<std::size_t>(hsize);
                     b < end; ++b) {
                    ct[b] ^= 0x01;
                }
                try {
                    (void) itb::decrypt_auth_triple(n, d1, d2, d3,
                                                    s1, s2, s3, mac, ct);
                    FAIL("expected MAC_FAILURE on tampered triple ciphertext");
                } catch (const itb::ItbError& e) {
                    REQUIRE(e.code() == itb::status::kMacFailure);
                }
            }
        }
    }
}

TEST_CASE("auth cross-MAC different primitive rejected",
          "[auth][cross_primitive]") {
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    itb::Mac enc_mac{"kmac256",     kKeyBytes};
    itb::Mac dec_mac{"hmac-sha256", kKeyBytes};

    static const std::uint8_t plaintext_bytes[] = "authenticated payload";
    std::vector<std::uint8_t> plaintext(
        plaintext_bytes, plaintext_bytes + sizeof(plaintext_bytes) - 1);

    auto ct = itb::encrypt_auth(n, d, s, enc_mac, plaintext);
    try {
        (void) itb::decrypt_auth(n, d, s, dec_mac, ct);
        FAIL("expected MAC_FAILURE on cross-primitive MAC");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kMacFailure);
    }
}

TEST_CASE("auth cross-MAC same primitive different key rejected",
          "[auth][cross_key]") {
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    std::vector<std::uint8_t> key_a(32, 0x01);
    std::vector<std::uint8_t> key_b(32, 0x02);

    itb::Mac enc_mac{"hmac-sha256", key_a};
    itb::Mac dec_mac{"hmac-sha256", key_b};

    static const std::uint8_t plaintext_bytes[] = "authenticated payload";
    std::vector<std::uint8_t> plaintext(
        plaintext_bytes, plaintext_bytes + sizeof(plaintext_bytes) - 1);

    auto ct = itb::encrypt_auth(n, d, s, enc_mac, plaintext);
    try {
        (void) itb::decrypt_auth(n, d, s, dec_mac, ct);
        FAIL("expected MAC_FAILURE on differing MAC key");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kMacFailure);
    }
}

TEST_CASE("auth tag-tail flip surfaces MAC_FAILURE", "[auth][tag_flip]") {
    itb::Seed n{"blake3", 1024};
    itb::Seed d{"blake3", 1024};
    itb::Seed s{"blake3", 1024};

    std::vector<std::uint8_t> key(32, 0);
    itb::Mac mac{"hmac-sha256", key};

    static const std::uint8_t pt_bytes[] = "payload-for-tag-flip";
    std::vector<std::uint8_t> plaintext(pt_bytes, pt_bytes + sizeof(pt_bytes) - 1);

    auto ct = itb::encrypt_auth(n, d, s, mac, plaintext);
    REQUIRE(!ct.empty());
    // Flip the last byte to tamper with the trailing MAC tag.
    ct.back() ^= 0xff;
    try {
        (void) itb::decrypt_auth(n, d, s, mac, ct);
        FAIL("expected MAC_FAILURE on tag-tail flip");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kMacFailure);
    }
}
