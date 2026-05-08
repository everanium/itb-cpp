// test_streams.cpp — class + free-function streaming smoke coverage.
//
// Round-trips a multi-chunk plaintext through every stream wrapper
// surface exposed by the binding:
//
//   - StreamEncryptor + StreamDecryptor          (Single Ouroboros)
//   - StreamEncryptorTriple + StreamDecryptorTriple (Triple Ouroboros)
//   - encrypt_stream + decrypt_stream            (free, Single)
//   - encrypt_stream_triple + decrypt_stream_triple (free, Triple)
//
// Confirms three structural properties: (a) close() flushes a
// trailing partial chunk on the encryptor side; (b) feed() of a
// half-chunk to the decryptor + close() raises ItbError(kBadInput)
// (trailing bytes); (c) several chunk_size choices all round-trip.
//
// Mirrors bindings/c/tests/test_easy_streams.c chunk-by-chunk
// orchestration on the C++ surface.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

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

// Helper closure pair: source draining from a vector, sink appending to
// a vector. Returned as std::function instances for the free-function
// streams API.
struct VecSource {
    const std::vector<std::uint8_t>* src;
    std::size_t off = 0;
    std::size_t operator()(std::uint8_t* buf, std::size_t cap) {
        std::size_t avail = src->size() - off;
        std::size_t n = (cap < avail) ? cap : avail;
        for (std::size_t i = 0; i < n; ++i) buf[i] = (*src)[off + i];
        off += n;
        return n;
    }
};

} // namespace

TEST_CASE("StreamEncryptor + StreamDecryptor round-trip multi-chunk",
          "[streams][single][class]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    constexpr std::size_t kPtLen = 100u * 1024u;       // 100 KiB
    constexpr std::size_t kChunk = 32u * 1024u;        // ~4 chunks
    auto pt = token_bytes(kPtLen);

    std::vector<std::uint8_t> ciphertext;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ciphertext.insert(ciphertext.end(), p, p + n);
    };
    {
        itb::StreamEncryptor enc{noise, data, start, sink_ct, kChunk};
        // Feed in ~3 KiB chunks to exercise the internal buffer
        // accumulation and flush-on-threshold logic.
        constexpr std::size_t kFeed = 3072;
        for (std::size_t off = 0; off < pt.size(); off += kFeed) {
            std::size_t end = off + kFeed;
            if (end > pt.size()) end = pt.size();
            enc.write(pt.data() + off, end - off);
        }
        enc.close();
    }
    REQUIRE(!ciphertext.empty());

    std::vector<std::uint8_t> recovered;
    auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    {
        itb::StreamDecryptor dec{noise, data, start, sink_pt};
        // Feed ciphertext in ~5 KiB shards to exercise the drain loop.
        constexpr std::size_t kFeed = 5120;
        for (std::size_t off = 0; off < ciphertext.size(); off += kFeed) {
            std::size_t end = off + kFeed;
            if (end > ciphertext.size()) end = ciphertext.size();
            dec.feed(ciphertext.data() + off, end - off);
        }
        dec.close();
    }
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamEncryptorTriple + StreamDecryptorTriple round-trip",
          "[streams][triple][class]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

    constexpr std::size_t kPtLen = 100u * 1024u;
    constexpr std::size_t kChunk = 32u * 1024u;
    auto pt = token_bytes(kPtLen);

    std::vector<std::uint8_t> ct;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    {
        itb::StreamEncryptorTriple enc{noise, d1, d2, d3, s1, s2, s3,
                                       sink_ct, kChunk};
        enc.write(pt);
        enc.close();
    }
    REQUIRE(!ct.empty());

    std::vector<std::uint8_t> recovered;
    auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    {
        itb::StreamDecryptorTriple dec{noise, d1, d2, d3, s1, s2, s3,
                                       sink_pt};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

TEST_CASE("encrypt_stream + decrypt_stream free-function round-trip",
          "[streams][single][free]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    constexpr std::size_t kPtLen = 80u * 1024u;
    constexpr std::size_t kChunk = 24u * 1024u;
    auto pt = token_bytes(kPtLen);

    VecSource pt_src{&pt, 0};
    std::vector<std::uint8_t> ct;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::encrypt_stream(noise, data, start,
                                        std::ref(pt_src), sink_ct,
                                        kChunk));
    REQUIRE(!ct.empty());

    VecSource ct_src{&ct, 0};
    std::vector<std::uint8_t> recovered;
    auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::decrypt_stream(noise, data, start,
                                        std::ref(ct_src), sink_pt,
                                        kChunk));
    REQUIRE(recovered == pt);
}

TEST_CASE("encrypt_stream_triple + decrypt_stream_triple free-function "
          "round-trip", "[streams][triple][free]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

    constexpr std::size_t kPtLen = 80u * 1024u;
    constexpr std::size_t kChunk = 24u * 1024u;
    auto pt = token_bytes(kPtLen);

    VecSource pt_src{&pt, 0};
    std::vector<std::uint8_t> ct;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::encrypt_stream_triple(noise, d1, d2, d3,
                                               s1, s2, s3,
                                               std::ref(pt_src), sink_ct,
                                               kChunk));
    REQUIRE(!ct.empty());

    VecSource ct_src{&ct, 0};
    std::vector<std::uint8_t> recovered;
    auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    REQUIRE_NOTHROW(itb::decrypt_stream_triple(noise, d1, d2, d3,
                                               s1, s2, s3,
                                               std::ref(ct_src), sink_pt,
                                               kChunk));
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamDecryptor::close raises on trailing partial chunk",
          "[streams][single][trailing]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    // Produce a ciphertext stream first.
    constexpr std::size_t kChunk = 4096;
    auto pt = token_bytes(8192);
    std::vector<std::uint8_t> ct;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    {
        itb::StreamEncryptor enc{noise, data, start, sink_ct, kChunk};
        enc.write(pt);
        enc.close();
    }
    REQUIRE(ct.size() > 64);

    // Feed only a partial slice to the decoder — the header is parsed
    // (>= 20 bytes default) but the body is incomplete. close() must
    // surface kBadInput.
    auto sink_pt = [](const std::uint8_t*, std::size_t) {};
    itb::StreamDecryptor dec{noise, data, start, sink_pt};
    constexpr std::size_t kPartial = 30;
    dec.feed(ct.data(), kPartial);
    try {
        dec.close();
        FAIL("expected ItbError(kBadInput) on trailing bytes");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("StreamDecryptorTriple::close raises on trailing partial chunk",
          "[streams][triple][trailing]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

    constexpr std::size_t kChunk = 4096;
    auto pt = token_bytes(8192);
    std::vector<std::uint8_t> ct;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
    };
    {
        itb::StreamEncryptorTriple enc{noise, d1, d2, d3, s1, s2, s3,
                                       sink_ct, kChunk};
        enc.write(pt);
        enc.close();
    }
    REQUIRE(ct.size() > 64);

    auto sink_pt = [](const std::uint8_t*, std::size_t) {};
    itb::StreamDecryptorTriple dec{noise, d1, d2, d3, s1, s2, s3, sink_pt};
    constexpr std::size_t kPartial = 30;
    dec.feed(ct.data(), kPartial);
    try {
        dec.close();
        FAIL("expected ItbError(kBadInput) on trailing bytes");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("StreamEncryptor flushes a single trailing chunk on close",
          "[streams][single][flush]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();

    // Plaintext smaller than chunk_size: no whole-chunk flush during
    // write; the trailing partial flushes as the final chunk in close.
    constexpr std::size_t kChunk = 16384;
    auto pt = token_bytes(100);

    std::vector<std::uint8_t> ct;
    int chunk_count = 0;
    auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
        ct.insert(ct.end(), p, p + n);
        ++chunk_count;
    };
    {
        itb::StreamEncryptor enc{noise, data, start, sink_ct, kChunk};
        enc.write(pt);
        enc.close();
    }
    REQUIRE(chunk_count == 1);

    // Round-trip back through the decoder for a sanity check.
    std::vector<std::uint8_t> recovered;
    auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
        recovered.insert(recovered.end(), p, p + n);
    };
    itb::StreamDecryptor dec{noise, data, start, sink_pt};
    dec.feed(ct);
    dec.close();
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamEncryptor + Decryptor round-trip across chunk_sizes",
          "[streams][single][chunk_sizes]") {
    const std::size_t kChunkSizes[] = {1024, 16384, 65536};
    auto pt = token_bytes(80u * 1024u);

    for (std::size_t cs : kChunkSizes) {
        SECTION(std::string{"chunk_size="} + std::to_string(cs)) {
            auto noise = make_seed();
            auto data  = make_seed();
            auto start = make_seed();

            std::vector<std::uint8_t> ct;
            auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
                ct.insert(ct.end(), p, p + n);
            };
            {
                itb::StreamEncryptor enc{noise, data, start, sink_ct, cs};
                enc.write(pt);
                enc.close();
            }
            REQUIRE(!ct.empty());

            std::vector<std::uint8_t> recovered;
            auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
                recovered.insert(recovered.end(), p, p + n);
            };
            {
                itb::StreamDecryptor dec{noise, data, start, sink_pt};
                dec.feed(ct);
                dec.close();
            }
            REQUIRE(recovered == pt);
        }
    }
}
