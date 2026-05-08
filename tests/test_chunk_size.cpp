// test_chunk_size.cpp — chunk_size > 0 preflight on every stream entry.
//
// chunk_size = 0 in the StreamEncryptor / StreamDecryptor (Single)
// constructor, the StreamEncryptorTriple / StreamDecryptorTriple
// constructor, and the four free functions surfaces as
// ItbError(kBadInput). chunk_size = 1 (the smallest positive value)
// must round-trip a small payload cleanly.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

void noop_sink(const std::uint8_t*, std::size_t) {}

std::size_t empty_source(std::uint8_t*, std::size_t) { return 0; }

} // namespace

TEST_CASE("StreamEncryptor rejects chunk_size = 0",
          "[chunk_size][stream][single]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    try {
        itb::StreamEncryptor enc{noise, data, start, &noop_sink, 0};
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("StreamEncryptorTriple rejects chunk_size = 0",
          "[chunk_size][stream][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    try {
        itb::StreamEncryptorTriple enc{noise, d1, d2, d3, s1, s2, s3,
                                       &noop_sink, 0};
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

// Note. StreamDecryptor and StreamDecryptorTriple do not take a
// chunk_size argument in their constructors — the chunk header itself
// carries the per-chunk length. The chunk_size > 0 preflight applies
// to encryptor classes and to the four free functions.

TEST_CASE("encrypt_stream rejects chunk_size = 0",
          "[chunk_size][free][single]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    try {
        itb::encrypt_stream(noise, data, start,
                            &empty_source, &noop_sink, 0);
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("decrypt_stream rejects chunk_size = 0",
          "[chunk_size][free][single]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    try {
        itb::decrypt_stream(noise, data, start,
                            &empty_source, &noop_sink, 0);
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("encrypt_stream_triple rejects chunk_size = 0",
          "[chunk_size][free][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    try {
        itb::encrypt_stream_triple(noise, d1, d2, d3, s1, s2, s3,
                                   &empty_source, &noop_sink, 0);
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("decrypt_stream_triple rejects chunk_size = 0",
          "[chunk_size][free][triple]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    try {
        itb::decrypt_stream_triple(noise, d1, d2, d3, s1, s2, s3,
                                   &empty_source, &noop_sink, 0);
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("StreamEncryptor + Decryptor round-trip with chunk_size = 1",
          "[chunk_size][stream][single][min]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    std::vector<std::uint8_t> ciphertext;
    auto sink = [&](const std::uint8_t* p, std::size_t len) {
        ciphertext.insert(ciphertext.end(), p, p + len);
    };
    std::vector<std::uint8_t> recovered;
    auto sink2 = [&](const std::uint8_t* p, std::size_t len) {
        recovered.insert(recovered.end(), p, p + len);
    };

    const std::vector<std::uint8_t> pt{'1', '2', '3', '4', '5',
                                       '6', '7', '8', '9', 'A'};
    itb::StreamEncryptor enc{noise, data, start, sink, 1};
    enc.write(pt);
    enc.close();
    REQUIRE(!ciphertext.empty());

    itb::StreamDecryptor dec{noise, data, start, sink2};
    dec.feed(ciphertext);
    dec.close();
    REQUIRE(recovered == pt);
}

TEST_CASE("encrypt_stream + decrypt_stream round-trip with chunk_size = 1",
          "[chunk_size][free][single][min]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    const std::vector<std::uint8_t> pt{'A', 'b', 'C', 'd', 'E',
                                       'f', 'G', 'h', 'I', 'j'};
    std::size_t read_off = 0;
    auto src = [&](std::uint8_t* buf, std::size_t cap) -> std::size_t {
        std::size_t avail = pt.size() - read_off;
        std::size_t n = (cap < avail) ? cap : avail;
        for (std::size_t i = 0; i < n; ++i) buf[i] = pt[read_off + i];
        read_off += n;
        return n;
    };
    std::vector<std::uint8_t> ct;
    auto write_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::encrypt_stream(noise, data, start, src,
                                        write_ct, 1));
    REQUIRE(!ct.empty());

    std::size_t read_ct_off = 0;
    auto src_ct = [&](std::uint8_t* buf, std::size_t cap) -> std::size_t {
        std::size_t avail = ct.size() - read_ct_off;
        std::size_t n = (cap < avail) ? cap : avail;
        for (std::size_t i = 0; i < n; ++i) buf[i] = ct[read_ct_off + i];
        read_ct_off += n;
        return n;
    };
    std::vector<std::uint8_t> recovered;
    auto write_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::decrypt_stream(noise, data, start, src_ct,
                                        write_pt, 1));
    REQUIRE(recovered == pt);
}
