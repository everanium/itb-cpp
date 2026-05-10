// test_easy_streams_auth.cpp — encryptor-bound Streaming AEAD round-trip
// + tamper detection via the encryptor_stream_encrypt_auth /
// encryptor_stream_decrypt_auth free functions.
//
// Mirrors bindings/c/tests/test_easy_streams_auth.c on the C++ surface.
// The encryptor's bound MAC closure is reused across every chunk; the
// helper supplies the Streaming AEAD binding components internally.
//
// The free-function helpers take an `itb_encryptor_t*` raw handle
// extracted from `Encryptor::raw_handle()`. Closed-state preflight
// surfaces as `ItbError(kEasyClosed)`. End-of-stream errors materialise
// as `ItbStreamTruncatedError` / `ItbStreamAfterFinalError` typed
// exceptions.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kSmallChunk = 4096;

std::vector<std::uint8_t> pseudo_payload(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>(((i * 31u) + 17u) & 0xffu);
    }
    return out;
}

struct VecSource {
    const std::vector<std::uint8_t>* src;
    std::size_t off = 0;
    std::size_t cap_per_call = 0;
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

struct VecSink {
    std::vector<std::uint8_t>* dst;
    void operator()(const std::uint8_t* p, std::size_t n) {
        dst->insert(dst->end(), p, p + n);
    }
};

// Builds a paired pair of encryptors over the same primitive/mode/key
// material via export -> import on a sibling instance.
std::pair<itb::Encryptor, itb::Encryptor> make_paired(
    std::string_view primitive, int key_bits,
    std::string_view mac, int mode) {
    itb::Encryptor enc{primitive, key_bits, mac, mode};
    auto blob = enc.export_state();
    itb::Encryptor sib{primitive, key_bits, mac, mode};
    sib.import_state(blob);
    return {std::move(enc), std::move(sib)};
}

} // namespace

TEST_CASE("encryptor stream-auth single round-trip default",
          "[easy_streams_auth][single]") {
    auto [enc, sib] = make_paired("blake3", 1024, "", 1);

    auto pt = pseudo_payload(kSmallChunk * 3 + 13);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                       std::ref(src2), VecSink{&recovered},
                                       kSmallChunk);
    REQUIRE(recovered == pt);
}

TEST_CASE("encryptor stream-auth triple round-trip kmac256",
          "[easy_streams_auth][triple]") {
    auto [enc, sib] = make_paired("blake3", 1024, "kmac256", 3);

    auto pt = pseudo_payload(kSmallChunk * 2 + 47);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt, 0, 1024};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct, 0, 1024};
    itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                       std::ref(src2), VecSink{&recovered},
                                       kSmallChunk);
    REQUIRE(recovered == pt);
}

TEST_CASE("encryptor stream-auth empty stream",
          "[easy_streams_auth][empty]") {
    auto [enc, sib] = make_paired("blake3", 1024, "", 1);

    std::vector<std::uint8_t> empty_pt;
    std::vector<std::uint8_t> ct;
    VecSource src{&empty_pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);
    REQUIRE(ct.size() > 32u);

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                       std::ref(src2), VecSink{&recovered},
                                       kSmallChunk);
    REQUIRE(recovered.empty());
}

TEST_CASE("encryptor stream-auth detects truncate-tail",
          "[easy_streams_auth][tamper][truncate]") {
    auto [enc, sib] = make_paired("blake3", 1024, "", 1);

    auto pt = pseudo_payload(kSmallChunk * 3 - 5);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);
    int hsz = enc.header_size();
    REQUIRE(hsz > 0);
    // Walk to chunk 2 (the terminating chunk).
    std::size_t cur = 32;
    cur += enc.parse_chunk_len(ct.data() + cur,
                               static_cast<std::size_t>(hsz));
    cur += enc.parse_chunk_len(ct.data() + cur,
                               static_cast<std::size_t>(hsz));

    std::vector<std::uint8_t> truncated(
        ct.begin(),
        ct.begin() + static_cast<std::ptrdiff_t>(cur));

    std::vector<std::uint8_t> recovered;
    VecSource src2{&truncated};
    bool threw = false;
    try {
        itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                           std::ref(src2),
                                           VecSink{&recovered},
                                           kSmallChunk);
    } catch (const itb::ItbStreamTruncatedError&) {
        threw = true;
    }
    REQUIRE(threw);
}

TEST_CASE("encryptor stream-auth closed-encryptor preflight",
          "[easy_streams_auth][closed]") {
    itb::Encryptor enc{"blake3", 1024, "", 1};
    enc.close();

    std::vector<std::uint8_t> pt;
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    int code = 0;
    bool threw = false;
    try {
        itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                           std::ref(src), VecSink{&ct},
                                           kSmallChunk);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kEasyClosed);

    threw = false;
    code = 0;
    std::vector<std::uint8_t> recovered;
    VecSource src2{&pt};
    try {
        itb::encryptor_stream_decrypt_auth(enc.raw_handle(),
                                           std::ref(src2),
                                           VecSink{&recovered},
                                           kSmallChunk);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kEasyClosed);
}

TEST_CASE("encryptor stream-auth chunk_size = 0 rejected",
          "[easy_streams_auth][bad_input]") {
    itb::Encryptor enc{"blake3", 1024, "", 1};

    std::vector<std::uint8_t> pt;
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    int code = 0;
    bool threw = false;
    try {
        itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                           std::ref(src), VecSink{&ct},
                                           0);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kBadInput);
}

TEST_CASE("encryptor stream-auth detects stream-prefix tamper",
          "[easy_streams_auth][tamper][prefix]") {
    auto [enc, sib] = make_paired("blake3", 1024, "", 1);

    auto pt = pseudo_payload(500);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);

    // Flip one byte inside the 32-byte stream_id prefix.
    ct[10] ^= 0x33;

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    int code = 0;
    bool threw = false;
    try {
        itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                           std::ref(src2),
                                           VecSink{&recovered},
                                           kSmallChunk);
    } catch (const itb::ItbError& e) {
        threw = true;
        code = e.code();
    }
    REQUIRE(threw);
    REQUIRE(code == itb::status::kMacFailure);
}

namespace {

// Regression: per-instance nonce_bits must drive the auth-stream
// decoder's chunk-length parse, not the process-global setting.
// run_paired_auth_roundtrip_nonce_bits exercises encrypt + decrypt
// with a paired pair of encryptors at the requested per-instance
// nonce-bits value, over a multi-chunk plaintext.
void run_paired_auth_roundtrip_nonce_bits(int nonce_bits, int mode,
                                            std::string_view mac_name) {
    itb::Encryptor enc{"blake3", 1024, mac_name, mode};
    enc.set_nonce_bits(nonce_bits);
    auto blob = enc.export_state();
    itb::Encryptor sib{"blake3", 1024, mac_name, mode};
    sib.set_nonce_bits(nonce_bits);
    sib.import_state(blob);

    // ~96 KiB plaintext -> multi-chunk wire at kSmallChunk = 4096.
    auto pt = pseudo_payload(kSmallChunk * 24 + 17);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                       std::ref(src2), VecSink{&recovered},
                                       kSmallChunk);
    REQUIRE(recovered == pt);
}

} // namespace

TEST_CASE("encryptor stream-auth round-trip non-default nonce_bits single",
          "[easy_streams_auth][nonce_bits][single]") {
    for (int nb : {256, 512}) {
        run_paired_auth_roundtrip_nonce_bits(nb, 1, "");
    }
}

TEST_CASE("encryptor stream-auth round-trip non-default nonce_bits triple",
          "[easy_streams_auth][nonce_bits][triple]") {
    for (int nb : {256, 512}) {
        run_paired_auth_roundtrip_nonce_bits(nb, 3, "kmac256");
    }
}

TEST_CASE("encryptor stream-auth global diverges from instance nonce_bits",
          "[easy_streams_auth][nonce_bits][regression]") {
    // Pin the process-global at 128 (the default). The per-instance
    // value is then bumped to 512. Decryption must still succeed; if
    // the auth-stream parser silently consults the global, chunk_len
    // mismatches and the round-trip fails.
    itb::set_nonce_bits(128);
    REQUIRE(itb::get_nonce_bits() == 128);

    itb::Encryptor enc{"blake3", 1024, "", 1};
    enc.set_nonce_bits(512);
    auto blob = enc.export_state();
    itb::Encryptor sib{"blake3", 1024, "", 1};
    sib.set_nonce_bits(512);
    sib.import_state(blob);

    // The per-instance set must not leak into the global.
    REQUIRE(itb::get_nonce_bits() == 128);

    auto pt = pseudo_payload(kSmallChunk * 24 + 17);
    std::vector<std::uint8_t> ct;
    VecSource src{&pt};
    itb::encryptor_stream_encrypt_auth(enc.raw_handle(),
                                       std::ref(src), VecSink{&ct},
                                       kSmallChunk);

    std::vector<std::uint8_t> recovered;
    VecSource src2{&ct};
    itb::encryptor_stream_decrypt_auth(sib.raw_handle(),
                                       std::ref(src2), VecSink{&recovered},
                                       kSmallChunk);
    REQUIRE(recovered == pt);
}
