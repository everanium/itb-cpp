// test_streams_auth.cpp — Streaming AEAD round-trip + tamper detection
// over the seed-based StreamEncryptorAuth / StreamDecryptorAuth class
// pair plus the encrypt_stream_auth / decrypt_stream_auth free
// functions (Single + Triple Ouroboros).
//
// Mirrors bindings/c/tests/test_streams_auth.c on the C++ surface.
// Per coverage class enumerated by the Streaming AEAD design surface:
//
//   - Round-trip across (chunk_size x Single / Triple x MAC primitive)
//   - Empty stream + single-chunk + chunk_size = 1
//   - Reorder of two chunks               -> ItbError(kMacFailure)
//   - Truncate-tail (drop last chunk)     -> ItbStreamTruncatedError
//   - Cross-stream splice                  -> ItbError(kMacFailure)
//   - Stream-prefix tamper (flip 1 byte)   -> ItbError(kMacFailure)
//   - Closed-encryptor preflight on classes
//   - Move-only class lifetime semantics

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;
constexpr std::size_t kSmallChunk = 4096;

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

std::vector<std::uint8_t> make_key() {
    std::vector<std::uint8_t> k(32);
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<std::uint8_t>((i * 17u + 5u) & 0xffu);
    }
    return k;
}

std::vector<std::uint8_t> pseudo_payload(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>(((i * 13u) + 11u) & 0xffu);
    }
    return out;
}

// Source over a vector + offset, preserved by capturing reference.
struct VecSource {
    const std::vector<std::uint8_t>* src;
    std::size_t off = 0;
    std::size_t cap_per_call = 0; // 0 means no cap
    std::size_t operator()(std::uint8_t* buf, std::size_t cap) {
        std::size_t avail = src->size() - off;
        std::size_t n = (cap < avail) ? cap : avail;
        if (cap_per_call > 0 && n > cap_per_call) n = cap_per_call;
        if (n > 0) {
            std::memcpy(buf, src->data() + off, n);
            off += n;
        }
        return n;
    }
};

// Sink appending into a vector.
struct VecSink {
    std::vector<std::uint8_t>* dst;
    void operator()(const std::uint8_t* p, std::size_t n) {
        dst->insert(dst->end(), p, p + n);
    }
};

} // namespace

// ---- Round-trip across MAC primitives -----------------------------

TEST_CASE("StreamEncryptorAuth + StreamDecryptorAuth round-trip kmac256",
          "[streams_auth][single][class][kmac256]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"kmac256", make_key()};

    auto pt = pseudo_payload(kSmallChunk * 4 + 11);
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        enc.write(pt);
        enc.close();
    }
    REQUIRE(ct.size() > 32u);

    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamEncryptorAuth round-trip hmac-blake3 (chunked sink)",
          "[streams_auth][single][class][hmac_blake3]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(kSmallChunk * 3 + 7);
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        // Push in shards to exercise the internal queue.
        for (std::size_t off = 0; off < pt.size(); off += 1500) {
            std::size_t end = off + 1500;
            if (end > pt.size()) end = pt.size();
            enc.write(pt.data() + off, end - off);
        }
        enc.close();
    }

    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamEncryptorAuth round-trip hmac-sha256 short payload",
          "[streams_auth][single][class][hmac_sha256]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-sha256", make_key()};

    std::string payload = "auth stream short payload coverage";
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        enc.write(payload);
        enc.close();
    }
    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    std::vector<std::uint8_t> expected(payload.begin(), payload.end());
    REQUIRE(recovered == expected);
}

// ---- Empty stream / single-chunk / chunk_size = 1 -----------------

TEST_CASE("StreamEncryptorAuth empty stream",
          "[streams_auth][single][class][empty]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        enc.close();
    }
    REQUIRE(ct.size() > 32u);

    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered.empty());
}

TEST_CASE("StreamEncryptorAuth single chunk smaller than chunk_size",
          "[streams_auth][single][class][single_chunk]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(200);
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        enc.write(pt);
        enc.close();
    }
    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

TEST_CASE("StreamEncryptorAuth chunk_size = 1",
          "[streams_auth][single][class][cs1]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    std::vector<std::uint8_t> pt = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, /*chunk_size*/ 1};
        enc.write(pt);
        enc.close();
    }
    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, /*chunk_size*/ 1};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

// ---- Triple Ouroboros round-trip ----------------------------------

TEST_CASE("StreamEncryptorAuthTriple + StreamDecryptorAuthTriple round-trip",
          "[streams_auth][triple][class]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(kSmallChunk * 3 + 19);
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuthTriple enc{
            noise, d1, d2, d3, s1, s2, s3, mac,
            VecSink{&ct}, kSmallChunk};
        enc.write(pt);
        enc.close();
    }
    std::vector<std::uint8_t> recovered;
    {
        itb::StreamDecryptorAuthTriple dec{
            noise, d1, d2, d3, s1, s2, s3, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    }
    REQUIRE(recovered == pt);
}

// ---- Free-function round-trip -------------------------------------

TEST_CASE("encrypt_stream_auth + decrypt_stream_auth free-function",
          "[streams_auth][single][free]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(kSmallChunk * 2 + 17);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encrypt_stream_auth(noise, data, start, mac,
                             std::ref(src), VecSink{&ct},
                             kSmallChunk);
    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::decrypt_stream_auth(noise, data, start, mac,
                             std::ref(src2), VecSink{&recovered},
                             kSmallChunk);
    REQUIRE(recovered == pt);
}

TEST_CASE("encrypt_stream_auth_triple + decrypt_stream_auth_triple free-function",
          "[streams_auth][triple][free]") {
    auto noise = make_seed();
    auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
    auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(kSmallChunk * 2 + 47);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encrypt_stream_auth_triple(noise, d1, d2, d3, s1, s2, s3,
                                    mac, std::ref(src), VecSink{&ct},
                                    kSmallChunk);
    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::decrypt_stream_auth_triple(noise, d1, d2, d3, s1, s2, s3,
                                    mac, std::ref(src2), VecSink{&recovered},
                                    kSmallChunk);
    REQUIRE(recovered == pt);
}

// ---- Tamper detection ---------------------------------------------

namespace {

// Builds a 3-chunk transcript (2 full + 1 short tail). Returns the
// wire bytes plus per-chunk byte offsets into the wire array. Chunk 0
// starts at offset 32 (after the 32-byte stream_id prefix).
struct ThreeChunkWire {
    std::vector<std::uint8_t> bytes;
    std::size_t offsets[3];
    std::size_t lens[3];
};

ThreeChunkWire build_three_chunk_wire(const itb::Seed& noise,
                                      const itb::Seed& data,
                                      const itb::Seed& start,
                                      const itb::Mac& mac,
                                      std::size_t chunk_size) {
    auto pt = pseudo_payload(chunk_size * 3 - 7);
    ThreeChunkWire w;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&w.bytes}, chunk_size};
        enc.write(pt);
        enc.close();
    }
    int hsz = itb_header_size();
    REQUIRE(hsz > 0);
    std::size_t cur = 32;
    for (int i = 0; i < 3; ++i) {
        w.offsets[i] = cur;
        std::size_t cl = 0;
        int rc = itb_parse_chunk_len(w.bytes.data() + cur,
                                     static_cast<std::size_t>(hsz), &cl);
        REQUIRE(rc == ITB_OK);
        w.lens[i] = cl;
        cur += cl;
    }
    REQUIRE(cur == w.bytes.size());
    return w;
}

} // namespace

TEST_CASE("StreamDecryptorAuth detects reorder of two chunks",
          "[streams_auth][tamper][reorder]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto w = build_three_chunk_wire(noise, data, start, mac, kSmallChunk);
    REQUIRE(w.lens[0] == w.lens[1]);

    // Swap chunks 0 and 1 in place.
    std::vector<std::uint8_t> tmp(w.lens[0]);
    std::memcpy(tmp.data(), w.bytes.data() + w.offsets[0], w.lens[0]);
    std::memcpy(w.bytes.data() + w.offsets[0],
                w.bytes.data() + w.offsets[1], w.lens[1]);
    std::memcpy(w.bytes.data() + w.offsets[1], tmp.data(), w.lens[0]);

    std::vector<std::uint8_t> recovered;
    bool threw = false;
    int code = 0;
    try {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(w.bytes);
        dec.close();
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kMacFailure);
}

TEST_CASE("StreamDecryptorAuth detects truncate-tail",
          "[streams_auth][tamper][truncate]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto w = build_three_chunk_wire(noise, data, start, mac, kSmallChunk);
    // Drop chunk 2: feed only [0 .. offsets[2]).
    std::vector<std::uint8_t> truncated(
        w.bytes.begin(),
        w.bytes.begin() + static_cast<std::ptrdiff_t>(w.offsets[2]));

    std::vector<std::uint8_t> recovered;
    bool threw_truncated = false;
    try {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(truncated);
        dec.close();
    } catch (const itb::ItbStreamTruncatedError&) {
        threw_truncated = true;
    } catch (const itb::ItbError& e) {
        FAIL("expected ItbStreamTruncatedError, got code=" << e.code());
    }
    REQUIRE(threw_truncated);
}

TEST_CASE("StreamDecryptorAuth detects stream-prefix tamper",
          "[streams_auth][tamper][prefix]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt = pseudo_payload(kSmallChunk + 5);
    std::vector<std::uint8_t> ct;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, kSmallChunk};
        enc.write(pt);
        enc.close();
    }
    // Flip a byte inside the 32-byte stream_id prefix.
    ct[5] ^= 0x55;

    std::vector<std::uint8_t> recovered;
    int code = 0;
    bool threw = false;
    try {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct);
        dec.close();
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kMacFailure);
}

// Builds a 2-chunk transcript (1 full + 1 short tail) and returns the
// wire bytes plus per-chunk byte offsets. Mirrors the 3-chunk helper
// at minimum payload — sufficient to surface the trailing-bytes-after-
// terminator decoder path.
namespace {

struct TwoChunkWire {
    std::vector<std::uint8_t> bytes;
    std::size_t offsets[2];
    std::size_t lens[2];
};

TwoChunkWire build_two_chunk_wire(const itb::Seed& noise,
                                  const itb::Seed& data,
                                  const itb::Seed& start,
                                  const itb::Mac& mac,
                                  std::size_t chunk_size) {
    auto pt = pseudo_payload(chunk_size + 11);
    TwoChunkWire w;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&w.bytes}, chunk_size};
        enc.write(pt);
        enc.close();
    }
    int hsz = itb_header_size();
    REQUIRE(hsz > 0);
    std::size_t cur = 32;
    for (int i = 0; i < 2; ++i) {
        w.offsets[i] = cur;
        std::size_t cl = 0;
        int rc = itb_parse_chunk_len(w.bytes.data() + cur,
                                     static_cast<std::size_t>(hsz), &cl);
        REQUIRE(rc == ITB_OK);
        w.lens[i] = cl;
        cur += cl;
    }
    REQUIRE(cur == w.bytes.size());
    return w;
}

} // namespace

TEST_CASE("StreamDecryptorAuth detects bytes after final chunk",
          "[streams_auth][tamper][after_final]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto w = build_two_chunk_wire(noise, data, start, mac, kSmallChunk);
    // Append a duplicate of the terminator (chunk 1) past the
    // terminating chunk. The decoder must observe the terminator and
    // then surface ItbStreamAfterFinalError on the trailing bytes.
    std::vector<std::uint8_t> with_extra = w.bytes;
    std::size_t extra_off = w.offsets[1];
    std::size_t extra_len = w.lens[1];
    with_extra.insert(with_extra.end(),
                      w.bytes.begin() + static_cast<std::ptrdiff_t>(extra_off),
                      w.bytes.begin() + static_cast<std::ptrdiff_t>(extra_off + extra_len));

    std::vector<std::uint8_t> recovered;
    bool threw_after_final = false;
    try {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(with_extra);
        dec.close();
    } catch (const itb::ItbStreamAfterFinalError&) {
        threw_after_final = true;
    } catch (const itb::ItbError& e) {
        FAIL("expected ItbStreamAfterFinalError, got code=" << e.code());
    }
    REQUIRE(threw_after_final);
}

TEST_CASE("StreamDecryptorAuth detects cross-stream replay",
          "[streams_auth][tamper][cross_stream]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt_a = pseudo_payload(kSmallChunk * 2 + 3);
    std::vector<std::uint8_t> pt_b(pt_a.size());
    for (std::size_t i = 0; i < pt_a.size(); ++i) {
        pt_b[i] = static_cast<std::uint8_t>(pt_a[i] ^ 0xaau);
    }

    std::vector<std::uint8_t> ct_a, ct_b;
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct_a}, kSmallChunk};
        enc.write(pt_a);
        enc.close();
    }
    {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct_b}, kSmallChunk};
        enc.write(pt_b);
        enc.close();
    }

    int hsz = itb_header_size();
    REQUIRE(hsz > 0);
    std::size_t a_off = 32, b_off = 32;
    std::size_t a_len = 0, b_len = 0;
    REQUIRE(itb_parse_chunk_len(ct_a.data() + a_off,
                                static_cast<std::size_t>(hsz), &a_len) == ITB_OK);
    REQUIRE(itb_parse_chunk_len(ct_b.data() + b_off,
                                static_cast<std::size_t>(hsz), &b_len) == ITB_OK);
    REQUIRE(a_len == b_len);
    std::memcpy(ct_b.data() + b_off, ct_a.data() + a_off, a_len);

    std::vector<std::uint8_t> recovered;
    int code = 0;
    bool threw = false;
    try {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered}, kSmallChunk};
        dec.feed(ct_b);
        dec.close();
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kMacFailure);
}

// ---- Closed-state preflight ---------------------------------------

TEST_CASE("StreamEncryptorAuth rejects write after close",
          "[streams_auth][closed]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    std::vector<std::uint8_t> ct;
    itb::StreamEncryptorAuth enc{
        noise, data, start, mac,
        VecSink{&ct}, kSmallChunk};
    enc.close();
    bool threw = false;
    int code = 0;
    try {
        std::uint8_t b = 0;
        enc.write(&b, 1);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kEasyClosed);
}

TEST_CASE("StreamDecryptorAuth rejects feed after close",
          "[streams_auth][closed]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    std::vector<std::uint8_t> dst;
    itb::StreamDecryptorAuth dec{
        noise, data, start, mac,
        VecSink{&dst}, kSmallChunk};
    // close() on an empty decoder triggers truncated detection
    // because no terminator chunk was observed; swallow it. The bare
    // `catch (const itb::ItbError&)` here intentionally absorbs the
    // truncated-tail signal — the focus of this test is that a feed
    // *after* close raises `kEasyClosed`, not the close-on-empty path
    // itself; the catch block keeps the scaffolding tight without
    // leaking error noise to test runners.
    try {
        dec.close();
    } catch (const itb::ItbError&) {
        // accepted
    }
    bool threw = false;
    int code = 0;
    try {
        std::uint8_t b = 0;
        dec.feed(&b, 1);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kEasyClosed);
}

TEST_CASE("StreamEncryptorAuth chunk_size = 0 rejected",
          "[streams_auth][bad_input]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    std::vector<std::uint8_t> ct;
    bool threw = false;
    int code = 0;
    try {
        itb::StreamEncryptorAuth enc{
            noise, data, start, mac,
            VecSink{&ct}, 0};
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kBadInput);
}

// ---- Move semantics -----------------------------------------------

TEST_CASE("StreamEncryptorAuth move-assignment flushes destination",
          "[streams_auth][move]") {
    auto noise = make_seed();
    auto data  = make_seed();
    auto start = make_seed();
    itb::Mac mac{"hmac-blake3", make_key()};

    auto pt_a = pseudo_payload(100);
    auto pt_b = pseudo_payload(150);
    std::vector<std::uint8_t> ct_a, ct_b;
    itb::StreamEncryptorAuth enc_a{
        noise, data, start, mac,
        VecSink{&ct_a}, kSmallChunk};
    enc_a.write(pt_a);

    itb::StreamEncryptorAuth enc_b{
        noise, data, start, mac,
        VecSink{&ct_b}, kSmallChunk};
    enc_b.write(pt_b);

    // Move-assigning enc_b into enc_a closes enc_a (flushing pt_a),
    // then adopts enc_b's queued plaintext.
    enc_a = std::move(enc_b);

    enc_a.close();

    REQUIRE_FALSE(ct_a.empty());
    REQUIRE_FALSE(ct_b.empty());

    // Round-trip both transcripts to confirm coherence.
    std::vector<std::uint8_t> recovered_a, recovered_b;
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered_a}, kSmallChunk};
        dec.feed(ct_a);
        dec.close();
    }
    {
        itb::StreamDecryptorAuth dec{
            noise, data, start, mac,
            VecSink{&recovered_b}, kSmallChunk};
        dec.feed(ct_b);
        dec.close();
    }
    REQUIRE(recovered_a == pt_a);
    REQUIRE(recovered_b == pt_b);
}
