// test_easy_streams.cpp — streaming-style use of the high-level
// Encryptor surface.
//
// Mirrors bindings/c/tests/test_easy_streams.c on the C++ surface.
// The Easy API does NOT expose dedicated stream helpers; streaming
// over an Encryptor lives entirely on the binding-side: the consumer
// slices plaintext into chunks of the desired size and calls
// Encryptor::encrypt per chunk. The decrypt side walks the
// concatenated chunk stream by reading Encryptor::header_size() bytes,
// calling Encryptor::parse_chunk_len, reading the remaining body, and
// feeding the full chunk to Encryptor::decrypt.
//
// This file therefore differs from test_streams.cpp, which exercises
// the seed-based StreamEncryptor / StreamDecryptor classes plus the
// encrypt_stream / decrypt_stream free functions. The two surfaces are
// independent: test_streams.cpp covers the one-shot read_fn / write_fn
// callback pair; this file covers the Encryptor-driven chunk loop with
// no class-level stream wrapper.
//
// Triple-Ouroboros (mode == 3) and non-default nonce_bits
// configurations are covered explicitly so a regression in
// Encryptor::header_size or Encryptor::parse_chunk_len surfaces here.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kSmallChunk = 4096;

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0x123456789ABCDEF0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

// Encrypts plaintext chunk-by-chunk through enc.encrypt and returns
// the concatenated ciphertext stream.
std::vector<std::uint8_t> stream_encrypt(itb::Encryptor& enc,
                                         const std::vector<std::uint8_t>& plaintext,
                                         std::size_t chunk_size) {
    std::vector<std::uint8_t> out;
    out.reserve(plaintext.size() + plaintext.size() / 4 + 64);
    std::size_t i = 0;
    while (i < plaintext.size()) {
        std::size_t end = i + chunk_size;
        if (end > plaintext.size()) {
            end = plaintext.size();
        }
        auto ct = enc.encrypt(plaintext.data() + i, end - i);
        out.insert(out.end(), ct.begin(), ct.end());
        i = end;
    }
    return out;
}

struct DrainResult {
    std::vector<std::uint8_t> recovered;
    bool trailing = false;
};

// Drains the concatenated ciphertext stream chunk-by-chunk by
// accumulating bytes into a binding-side buffer, calling
// parse_chunk_len once a full header is in scope, then handing the
// completed chunk to Encryptor::decrypt. Sets `trailing = true` and
// returns an empty `recovered` vector on a final partial-chunk
// remainder.
DrainResult stream_decrypt(itb::Encryptor& enc,
                           const std::vector<std::uint8_t>& ciphertext) {
    DrainResult res;
    int hs_int = enc.header_size();
    REQUIRE(hs_int > 0);
    std::size_t header_size = static_cast<std::size_t>(hs_int);

    std::vector<std::uint8_t> acc;
    acc.reserve(kSmallChunk * 2 + 64);

    std::size_t feed_off = 0;
    while (feed_off < ciphertext.size()) {
        std::size_t end = feed_off + kSmallChunk;
        if (end > ciphertext.size()) {
            end = ciphertext.size();
        }
        acc.insert(acc.end(),
                   ciphertext.begin() + static_cast<std::ptrdiff_t>(feed_off),
                   ciphertext.begin() + static_cast<std::ptrdiff_t>(end));
        feed_off = end;

        // Drain whole chunks.
        for (;;) {
            if (acc.size() < header_size) {
                break;
            }
            std::size_t chunk_len = enc.parse_chunk_len(acc.data(), header_size);
            if (acc.size() < chunk_len) {
                break;
            }
            auto pt = enc.decrypt(acc.data(), chunk_len);
            res.recovered.insert(res.recovered.end(), pt.begin(), pt.end());
            // Drain chunk_len bytes from the accumulator front.
            acc.erase(acc.begin(),
                      acc.begin() + static_cast<std::ptrdiff_t>(chunk_len));
        }
    }

    if (!acc.empty()) {
        res.recovered.clear();
        res.trailing = true;
    }
    return res;
}

} // namespace

TEST_CASE("streaming round-trip at default nonce_bits (single)",
          "[easy_streams][single][default_nonce]") {
    auto pt = token_bytes(kSmallChunk * 5 + 17);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    auto ct = stream_encrypt(enc, pt, kSmallChunk);
    auto drain = stream_decrypt(enc, ct);
    REQUIRE_FALSE(drain.trailing);
    REQUIRE(drain.recovered == pt);
}

TEST_CASE("streaming round-trip at non-default nonce_bits (single)",
          "[easy_streams][single][nonce]") {
    auto pt = token_bytes(kSmallChunk * 3 + 100);
    static const int kNonces[] = {256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
            enc.set_nonce_bits(nb);

            auto ct = stream_encrypt(enc, pt, kSmallChunk);
            auto drain = stream_decrypt(enc, ct);
            REQUIRE_FALSE(drain.trailing);
            REQUIRE(drain.recovered == pt);
        }
    }
}

TEST_CASE("streaming round-trip at default nonce_bits (triple)",
          "[easy_streams][triple][default_nonce]") {
    auto pt = token_bytes(kSmallChunk * 4 + 33);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 3};

    auto ct = stream_encrypt(enc, pt, kSmallChunk);
    auto drain = stream_decrypt(enc, ct);
    REQUIRE_FALSE(drain.trailing);
    REQUIRE(drain.recovered == pt);
}

TEST_CASE("streaming round-trip at non-default nonce_bits (triple)",
          "[easy_streams][triple][nonce]") {
    auto pt = token_bytes(kSmallChunk * 3);
    static const int kNonces[] = {256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            itb::Encryptor enc{"blake3", 1024, "kmac256", 3};
            enc.set_nonce_bits(nb);

            auto ct = stream_encrypt(enc, pt, kSmallChunk);
            auto drain = stream_decrypt(enc, ct);
            REQUIRE_FALSE(drain.trailing);
            REQUIRE(drain.recovered == pt);
        }
    }
}

TEST_CASE("streaming round-trip at varied chunk granularities",
          "[easy_streams][chunk_size]") {
    // Sender chunk_size and receiver drain are independent; the
    // receiver walks chunk boundaries via parse_chunk_len.
    auto pt = token_bytes(64u * 1024u + 333u);
    static const std::size_t kChunks[] = {1024u, 16u * 1024u, 64u * 1024u};
    for (std::size_t cs : kChunks) {
        SECTION(std::string{"chunk_size="} + std::to_string(cs)) {
            itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

            auto ct = stream_encrypt(enc, pt, cs);
            auto drain = stream_decrypt(enc, ct);
            REQUIRE_FALSE(drain.trailing);
            REQUIRE(drain.recovered == pt);
        }
    }
}

TEST_CASE("256-KiB plaintext sliced at 16 KiB round-trips end-to-end",
          "[easy_streams][large]") {
    // Larger payload exercises the per-chunk encrypt + drain loop
    // many times in one Encryptor instance, surfacing any per-call
    // accumulator regression.
    auto pt = token_bytes(256u * 1024u);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};

    auto ct = stream_encrypt(enc, pt, 16u * 1024u);
    auto drain = stream_decrypt(enc, ct);
    REQUIRE_FALSE(drain.trailing);
    REQUIRE(drain.recovered == pt);
}

TEST_CASE("partial trailing chunk surfaces as a trailing-bytes failure",
          "[easy_streams][partial]") {
    auto pt = token_bytes(100);
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    auto ct = stream_encrypt(enc, pt, kSmallChunk);

    // Feed only 30 bytes — header complete (>= 20 at default
    // nonce_bits) but body truncated. The drain loop must reject the
    // trailing incomplete chunk.
    std::vector<std::uint8_t> truncated(ct.begin(),
                                        ct.begin() + static_cast<std::ptrdiff_t>(30));
    auto drain = stream_decrypt(enc, truncated);
    REQUIRE(drain.trailing);
    REQUIRE(drain.recovered.empty());
}

TEST_CASE("parse_chunk_len rejects a header buffer shorter than header_size",
          "[easy_streams][parse_chunk_len][short]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    int hs = enc.header_size();
    REQUIRE(hs > 1);
    std::size_t cap = static_cast<std::size_t>(hs) - 1;
    std::vector<std::uint8_t> buf(cap, 0);

    try {
        (void)enc.parse_chunk_len(buf.data(), buf.size());
        FAIL("expected ItbError(kBadInput)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kBadInput);
    }
}

TEST_CASE("parse_chunk_len rejects a header with width == 0",
          "[easy_streams][parse_chunk_len][zero]") {
    itb::Encryptor enc{"blake3", 1024, "kmac256", 1};
    int hs = enc.header_size();
    REQUIRE(hs > 0);
    // header_size bytes, all zero — width and height fields are zero,
    // which the parser rejects.
    std::vector<std::uint8_t> hdr(static_cast<std::size_t>(hs), 0);
    REQUIRE_THROWS_AS(enc.parse_chunk_len(hdr.data(), hdr.size()),
                      itb::ItbError);
}
