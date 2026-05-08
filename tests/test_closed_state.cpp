// test_closed_state.cpp — closed-state preflight matrix.
//
// After Encryptor::close() (and the Stream class counterparts), every
// public method must raise ItbError with code()==status::kEasyClosed
// without round-tripping libitb. close() itself is idempotent — a
// second close() on an already-closed instance is a no-op. Move-from
// transfers the open state and leaves the source closed.
//
// Mirrors the closed-state subset of bindings/c/tests/test_easy.c
// (specifically test_easy_close_is_idempotent and the implicit
// closed-state contract enforced by the Encryptor wrapper).

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;
constexpr const char* kMac  = "hmac-blake3";

std::vector<std::uint8_t> sample_payload() {
    return std::vector<std::uint8_t>{'L', 'o', 'r', 'e', 'm', '!', '?', '#'};
}

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

void noop_sink(const std::uint8_t*, std::size_t) {}

} // namespace

TEST_CASE("encryptor close idempotent and is_closed flips",
          "[closed][encryptor]") {
    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    REQUIRE_FALSE(enc.is_closed());
    REQUIRE_NOTHROW(enc.close());
    REQUIRE(enc.is_closed());
    REQUIRE_NOTHROW(enc.close());
    REQUIRE(enc.is_closed());
}

TEST_CASE("encryptor closed-state preflight on every public method",
          "[closed][encryptor]") {
    // Build state we can replay through import_state in dedicated SECTION.
    std::vector<std::uint8_t> blob;
    {
        itb::Encryptor src{kPrim, kKb, kMac, 1};
        blob = src.export_state();
    }
    auto pt  = sample_payload();
    auto hdr = std::vector<std::uint8_t>(64, 0);

    itb::Encryptor enc{kPrim, kKb, kMac, 1};
    enc.close();
    REQUIRE(enc.is_closed());

    auto check_closed = [](auto&& callable) {
        try {
            callable();
            FAIL("expected ItbError(kEasyClosed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyClosed);
        }
    };

    SECTION("cipher entry points") {
        check_closed([&]{ enc.encrypt(pt); });
        check_closed([&]{ enc.decrypt(pt); });
        check_closed([&]{ enc.encrypt_auth(pt); });
        check_closed([&]{ enc.decrypt_auth(pt); });
    }
    SECTION("setters") {
        check_closed([&]{ enc.set_nonce_bits(256); });
        check_closed([&]{ enc.set_barrier_fill(4); });
        check_closed([&]{ enc.set_bit_soup(1); });
        check_closed([&]{ enc.set_lock_soup(1); });
        check_closed([&]{ enc.set_lock_seed(1); });
        check_closed([&]{ enc.set_chunk_size(1024); });
    }
    SECTION("read-only field accessors") {
        check_closed([&]{ (void)enc.primitive(); });
        check_closed([&]{ (void)enc.primitive_at(0); });
        check_closed([&]{ (void)enc.mac_name(); });
        check_closed([&]{ (void)enc.key_bits(); });
        check_closed([&]{ (void)enc.mode(); });
        check_closed([&]{ (void)enc.seed_count(); });
        check_closed([&]{ (void)enc.nonce_bits(); });
        check_closed([&]{ (void)enc.header_size(); });
        check_closed([&]{ (void)enc.has_prf_keys(); });
        check_closed([&]{ (void)enc.is_mixed(); });
        check_closed([&]{ (void)enc.parse_chunk_len(hdr); });
    }
    SECTION("material getters") {
        check_closed([&]{ (void)enc.seed_components(0); });
        check_closed([&]{ (void)enc.prf_key(0); });
        check_closed([&]{ (void)enc.mac_key(); });
    }
    SECTION("persistence") {
        check_closed([&]{ (void)enc.export_state(); });
        check_closed([&]{ enc.import_state(blob); });
    }
}

TEST_CASE("encryptor move-from leaves source closed",
          "[closed][encryptor][move]") {
    itb::Encryptor src{kPrim, kKb, kMac, 1};
    REQUIRE_FALSE(src.is_closed());

    auto dst = std::move(src);
    REQUIRE(src.is_closed());
    REQUIRE_FALSE(dst.is_closed());

    // The destination is fully usable.
    auto pt = sample_payload();
    auto ct = dst.encrypt(pt);
    REQUIRE(dst.decrypt(ct) == pt);

    // Operations on the moved-from source raise kEasyClosed.
    REQUIRE_THROWS_AS(src.encrypt(pt), itb::ItbError);
}

TEST_CASE("encryptor move-assign leaves source closed",
          "[closed][encryptor][move]") {
    itb::Encryptor a{kPrim, kKb, kMac, 1};
    itb::Encryptor b{kPrim, kKb, kMac, 3};
    REQUIRE(b.mode() == 3);

    b = std::move(a);
    REQUIRE(a.is_closed());
    REQUIRE_FALSE(b.is_closed());
    REQUIRE(b.mode() == 1); // adopted from a

    REQUIRE_THROWS_AS(a.mode(), itb::ItbError);
}

TEST_CASE("StreamEncryptor closed-state preflight", "[closed][stream]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    std::vector<std::uint8_t> sink_buf;
    auto sink = [&](const std::uint8_t* p, std::size_t n) {
        sink_buf.insert(sink_buf.end(), p, p + n);
    };

    itb::StreamEncryptor enc{noise, data, start, sink, 4096};
    REQUIRE_FALSE(enc.is_closed());

    auto pt = sample_payload();
    REQUIRE_NOTHROW(enc.write(pt));
    REQUIRE_NOTHROW(enc.close());
    REQUIRE(enc.is_closed());
    // Idempotent close.
    REQUIRE_NOTHROW(enc.close());

    try {
        enc.write(pt);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}

TEST_CASE("StreamDecryptor closed-state preflight", "[closed][stream]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    itb::StreamDecryptor dec{noise, data, start, &noop_sink};
    REQUIRE_FALSE(dec.is_closed());
    REQUIRE_NOTHROW(dec.close());
    REQUIRE(dec.is_closed());
    REQUIRE_NOTHROW(dec.close()); // idempotent

    std::vector<std::uint8_t> any{1, 2, 3, 4};
    try {
        dec.feed(any);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}

TEST_CASE("StreamEncryptorTriple closed-state preflight",
          "[closed][stream][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

    std::vector<std::uint8_t> sink_buf;
    auto sink = [&](const std::uint8_t* p, std::size_t n) {
        sink_buf.insert(sink_buf.end(), p, p + n);
    };

    itb::StreamEncryptorTriple enc{noise, d1, d2, d3, s1, s2, s3,
                                   sink, 4096};
    REQUIRE_FALSE(enc.is_closed());
    auto pt = sample_payload();
    REQUIRE_NOTHROW(enc.write(pt));
    REQUIRE_NOTHROW(enc.close());
    REQUIRE_NOTHROW(enc.close()); // idempotent

    try {
        enc.write(pt);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}

TEST_CASE("StreamDecryptorTriple closed-state preflight",
          "[closed][stream][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

    itb::StreamDecryptorTriple dec{noise, d1, d2, d3, s1, s2, s3,
                                   &noop_sink};
    REQUIRE_FALSE(dec.is_closed());
    REQUIRE_NOTHROW(dec.close());
    REQUIRE_NOTHROW(dec.close()); // idempotent

    std::vector<std::uint8_t> any{1, 2, 3, 4};
    try {
        dec.feed(any);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}
