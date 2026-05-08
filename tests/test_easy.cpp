// test_easy.cpp — Encryptor (Easy Mode) cross-cutting smoke coverage.
//
// Mirrors the high-level Easy Mode smoke pattern from the C binding's
// test_easy.c and serves as the cross-cutting companion to the
// per-primitive test_easy_<primitive>.cpp suites and to
// test_easy_persistence.cpp / test_easy_nonce_sizes.cpp /
// test_easy_version_too_new.cpp.
//
// Coverage:
//   - Encryptor lifecycle: construct, Single + Triple round-trip,
//     idempotent close(), move-construction / move-assignment leave
//     the source closed.
//   - Default constructor arguments (empty primitive / empty mac /
//     key_bits = 0) select the libitb defaults: areion512 / 1024 /
//     hmac-blake3.
//   - Read-only accessors on a vanilla Single-Ouroboros encryptor:
//     primitive() / mac_name() / key_bits() / mode() / seed_count() /
//     nonce_bits() / header_size() / has_prf_keys() / is_mixed().
//   - Tamper rejection on Encryptor::decrypt: a flipped byte inside
//     the ciphertext body forces a non-OK decrypt result regardless
//     of the exact status code (DECRYPT_FAILED or BAD_INPUT depending
//     on which structural field the byte fell in).
//   - Per-instance setter round-trip: set_nonce_bits / set_barrier_fill
//     / set_bit_soup / set_lock_soup / set_chunk_size all preserve
//     their effect on subsequent encrypt + decrypt without leaking
//     into the process-global libitb state. The two-encryptors-isolated
//     check confirms a setter applied to one Encryptor leaves a peer
//     Encryptor's nonce_bits / behaviour untouched.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr const char* kPlaintext =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

std::vector<std::uint8_t> plaintext_vec() {
    const auto* p = reinterpret_cast<const std::uint8_t*>(kPlaintext);
    std::size_t len = 0;
    while (kPlaintext[len] != '\0') {
        ++len;
    }
    return std::vector<std::uint8_t>{p, p + len};
}

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0x9E3779B97F4A7C15ULL;
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

TEST_CASE("Encryptor single-ouroboros round-trip recovers plaintext",
          "[easy][single]") {
    auto pt = plaintext_vec();
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    auto ct = enc.encrypt(pt);
    REQUIRE_FALSE(ct.empty());
    // The ciphertext is structurally larger than the plaintext (header
    // + body framing), so the simple ct == pt comparison is never
    // accidentally true.
    REQUIRE(ct.size() > pt.size());

    auto recovered = enc.decrypt(ct);
    REQUIRE(recovered == pt);
}

TEST_CASE("Encryptor triple-ouroboros round-trip recovers plaintext",
          "[easy][triple]") {
    auto pt = plaintext_vec();
    itb::Encryptor enc{"areion512", 2048, "kmac256", 3};

    auto ct = enc.encrypt(pt);
    auto recovered = enc.decrypt(ct);
    REQUIRE(recovered == pt);
    REQUIRE(enc.mode() == 3);
    REQUIRE(enc.seed_count() == 7);
}

TEST_CASE("Encryptor read-only accessors reflect constructor arguments",
          "[easy][accessors]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    REQUIRE(enc.primitive() == "blake3");
    REQUIRE(enc.mac_name() == "kmac256");
    REQUIRE(enc.key_bits() == 1024);
    REQUIRE(enc.mode() == 1);
    REQUIRE(enc.seed_count() == 3);
    REQUIRE(enc.nonce_bits() == 128);
    REQUIRE(enc.header_size() == 20); // 128/8 + 4
    REQUIRE_FALSE(enc.is_mixed());
    // PRF keys exist for non-PRF primitives too: the libitb-side
    // construction always populates the per-slot key vault. The
    // accessor merely asserts that material has been initialised.
    REQUIRE(enc.has_prf_keys());
}

TEST_CASE("Encryptor default-argument constructor selects libitb defaults",
          "[easy][defaults]") {
    // Empty primitive / empty MAC / key_bits == 0 forwards as nullptr /
    // 0 to the C binding, which substitutes areion512 / 1024 /
    // hmac-blake3.
    itb::Encryptor enc{"", 0, "", 1};
    REQUIRE(enc.primitive() == "areion512");
    REQUIRE(enc.key_bits() == 1024);
    REQUIRE(enc.mode() == 1);
    REQUIRE(enc.mac_name() == "hmac-blake3");

    auto pt = plaintext_vec();
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("Encryptor::close is idempotent and post-close calls raise",
          "[easy][close]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    REQUIRE_FALSE(enc.is_closed());
    REQUIRE_NOTHROW(enc.close());
    REQUIRE(enc.is_closed());
    // Repeated close() returns silently.
    REQUIRE_NOTHROW(enc.close());

    // Subsequent cipher / accessor calls raise kEasyClosed.
    auto pt = plaintext_vec();
    try {
        (void)enc.encrypt(pt);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
    try {
        (void)enc.primitive();
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}

TEST_CASE("Encryptor move-construction transfers handle and closes the source",
          "[easy][move]") {
    auto pt = plaintext_vec();
    itb::Encryptor src{"blake3", 1024, "kmac256", 1};
    auto ct = src.encrypt(pt);

    itb::Encryptor dst{std::move(src)};
    REQUIRE(src.is_closed()); // NOLINT(bugprone-use-after-move)
    REQUIRE_FALSE(dst.is_closed());
    // The moved-into encryptor inherits the source's seed material and
    // therefore decrypts the source's ciphertext correctly.
    REQUIRE(dst.decrypt(ct) == pt);
}

TEST_CASE("Encryptor move-assignment transfers handle and closes the source",
          "[easy][move]") {
    auto pt = plaintext_vec();
    itb::Encryptor src{"blake3", 1024, "kmac256", 1};
    auto ct = src.encrypt(pt);

    itb::Encryptor dst{"areion256", 1024, "hmac-blake3", 1};
    dst = std::move(src);
    REQUIRE(src.is_closed()); // NOLINT(bugprone-use-after-move)
    REQUIRE_FALSE(dst.is_closed());
    REQUIRE(dst.decrypt(ct) == pt);
    // The previous receiver state has been released by move-assignment;
    // there is no observable handle leak (RAII destructor follows scope
    // exit).
}

TEST_CASE("decrypt rejects a tampered ciphertext", "[easy][tamper]") {
    auto pt = token_bytes(2048);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    auto ct = enc.encrypt(pt);

    // Zero out the width / height fields in the dynamic header
    // (the last 4 bytes of the header). This corrupts the structural
    // size declaration and forces decrypt to reject — without
    // tightening to a specific status code, since libitb may surface
    // either kBadInput on the parse or kDecryptFailed downstream.
    int hsize = enc.header_size();
    REQUIRE(hsize >= 4);
    REQUIRE(static_cast<std::size_t>(hsize) <= ct.size());
    auto wh_off = static_cast<std::size_t>(hsize) - 4u;
    ct[wh_off + 0] = 0;
    ct[wh_off + 1] = 0;
    ct[wh_off + 2] = 0;
    ct[wh_off + 3] = 0;

    REQUIRE_THROWS_AS(enc.decrypt(ct), itb::ItbError);
}

TEST_CASE("set_nonce_bits is preserved per-instance and changes header_size",
          "[easy][setters][nonce]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    enc.set_nonce_bits(256);
    REQUIRE(enc.nonce_bits() == 256);
    REQUIRE(enc.header_size() == 36); // 256/8 + 4

    auto pt = token_bytes(1024);
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("set_barrier_fill is accepted on valid powers of two",
          "[easy][setters][barrier]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    REQUIRE_NOTHROW(enc.set_barrier_fill(8));

    auto pt = token_bytes(512);
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("set_bit_soup is accepted and round-trip still succeeds",
          "[easy][setters][bitsoup]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    REQUIRE_NOTHROW(enc.set_bit_soup(1));

    auto pt = token_bytes(512);
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("set_lock_soup is accepted and round-trip still succeeds",
          "[easy][setters][locksoup]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    REQUIRE_NOTHROW(enc.set_lock_soup(1));

    auto pt = token_bytes(512);
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("set_chunk_size is accepted on multiple values", "[easy][setters][chunk]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    REQUIRE_NOTHROW(enc.set_chunk_size(4096));
    REQUIRE_NOTHROW(enc.set_chunk_size(0));
    REQUIRE_NOTHROW(enc.set_chunk_size(65536));

    auto pt = token_bytes(512);
    auto ct = enc.encrypt(pt);
    REQUIRE(enc.decrypt(ct) == pt);
}

TEST_CASE("per-instance setter on one Encryptor does not leak into a peer",
          "[easy][setters][isolation]") {
    // set_nonce_bits flips an instance-scoped atomic on the C binding
    // side — a peer Encryptor's nonce_bits / header_size accessor must
    // continue to report the unmodified default value.
    itb::Encryptor a{"blake3", 1024, "kmac256", 1};
    itb::Encryptor b{"blake3", 1024, "kmac256", 1};

    a.set_nonce_bits(512);
    REQUIRE(a.nonce_bits() == 512);
    REQUIRE(a.header_size() == 68); // 512/8 + 4

    REQUIRE(b.nonce_bits() == 128);
    REQUIRE(b.header_size() == 20);
}

TEST_CASE("parse_chunk_len reports the full ciphertext length",
          "[easy][parse_chunk_len]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    auto pt = token_bytes(1024);
    auto ct = enc.encrypt(pt);

    int hs = enc.header_size();
    REQUIRE(hs > 0);
    std::vector<std::uint8_t> hdr(ct.begin(), ct.begin() + hs);
    REQUIRE(enc.parse_chunk_len(hdr) == ct.size());
}

TEST_CASE("header_size matches nonce_bits / 8 + 4 on every supported width",
          "[easy][header_size]") {
    static const int kNonceBits[] = {128, 256, 512};
    for (int nb : kNonceBits) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
            enc.set_nonce_bits(nb);
            REQUIRE(enc.nonce_bits() == nb);
            REQUIRE(enc.header_size() == nb / 8 + 4);
        }
    }
}
