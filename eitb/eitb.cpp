// eitb.cpp — wrapper × ITB matrix runner for the C++ binding.
//
// Mirrors tools/eitb/main.go in the root repository, adapted for the
// C++ binding's asymmetry: there is no Streaming No MAC IO-Driven
// example (`noaead-easy-io` / `noaead-lowlevel-io` from the Go
// matrix) because the C++ binding does not expose a `std::ostream`
// / `std::istream` wrapper writer / reader pair for Non-AEAD
// streaming. The Non-AEAD streaming arm is the User-Driven Loop only.
//
// Matrix: 8 examples × 3 outer ciphers (aes / chacha / siphash) =
// 24 PASS/FAIL cells.
//
// Examples covered:
//
//   - aead-easy-io               Streaming AEAD Easy   (MAC Authenticated, IO-Driven)
//   - aead-lowlevel-io           Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
//   - noaead-easy-userloop       Streaming Easy        (No MAC, User-Driven Loop)
//   - noaead-lowlevel-userloop   Streaming Low-Level   (No MAC, User-Driven Loop)
//   - message-easy-nomac         Easy Single Message      (No MAC)
//   - message-easy-auth          Easy Single Message      (MAC Authenticated)
//   - message-lowlevel-nomac     Low-Level Single Message (No MAC)
//   - message-lowlevel-auth      Low-Level Single Message (MAC Authenticated)
//
// Single-message examples encrypt 1024 bytes; streaming examples
// encrypt 64 KiB through 16 KiB chunks. Each example runs sender +
// receiver in the same process, wraps the ITB ciphertext under the
// chosen outer cipher, hands the wrapped bytes to the receiver path,
// and verifies sha256 byte-equality of the recovered plaintext
// against the original.
//
// Usage:
//
//     ./eitb/build/eitb
//     ./eitb/build/eitb --example aead
//     ./eitb/build/eitb --cipher aes
//     ./eitb/build/eitb -v
//
// Defaults to wrap_in_place / unwrap_in_place for the message-mode
// examples (zero allocation, mutates the ciphertext / wire buffer
// directly). Commented `wrap` / `unwrap` alternatives respect
// immutability of the caller's input at the cost of one extra
// allocation per call.

#include <itb.hpp>
#include <itb/wrapper.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern "C" {
#include "sha256.h"
}

namespace {

constexpr std::size_t kSingleMessageBytes = 1024;
constexpr std::size_t kStreamBytes        = 64 * 1024;
constexpr std::size_t kStreamChunkSize    = 16 * 1024;

// Cipher list in the canonical project primitive order; matches
// wrapper.CipherNames in the Go-side wrapper package.
constexpr itb::wrapper::Cipher kCiphers[] = {
    itb::wrapper::Cipher::Areion256,
    itb::wrapper::Cipher::Areion512,
    itb::wrapper::Cipher::SipHash24,
    itb::wrapper::Cipher::Aes128Ctr,
    itb::wrapper::Cipher::Blake2b256,
    itb::wrapper::Cipher::Blake2b512,
    itb::wrapper::Cipher::Blake2s,
    itb::wrapper::Cipher::Blake3,
    itb::wrapper::Cipher::ChaCha20,
};

std::string hex_short(const std::uint8_t* digest) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(16, '\0');
    for (std::size_t i = 0; i < 8; ++i) {
        out[2 * i + 0] = kHex[(digest[i] >> 4) & 0xFu];
        out[2 * i + 1] = kHex[digest[i] & 0xFu];
    }
    return out;
}

std::string hex_full(const std::uint8_t* digest) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(static_cast<std::size_t>(ITB_EITB_SHA256_DIGEST_LEN) * 2, '\0');
    for (std::size_t i = 0; i < ITB_EITB_SHA256_DIGEST_LEN; ++i) {
        out[2 * i + 0] = kHex[(digest[i] >> 4) & 0xFu];
        out[2 * i + 1] = kHex[digest[i] & 0xFu];
    }
    return out;
}

std::vector<std::uint8_t> read_csprng(std::size_t n) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open /dev/urandom");
    }
    std::vector<std::uint8_t> out(n);
    f.read(reinterpret_cast<char*>(out.data()),
           static_cast<std::streamsize>(n));
    if (static_cast<std::size_t>(f.gcount()) != n) {
        throw std::runtime_error("short read from /dev/urandom");
    }
    return out;
}

// ----- Per-example results ------------------------------------------

struct RunResult {
    bool ok = false;
    std::size_t wire_n = 0;
    std::vector<std::uint8_t> recovered;
    std::string err_msg;
};

// ----- Encryptor / seed factories -----------------------------------

// Note. The Go-side tools/eitb sets NonceBits=512 across the matrix.
// The C / C++ binding's streams.cpp maintains a fixed 64-byte hdr_buf
// for the chunk-header parser; with NonceBits=512 a chunk header is
// 64+4 = 68 bytes, exceeding that buffer. The C++ binding's eitb
// therefore uses NonceBits=128 (the libitb default). Aside from the
// smaller chunk-header field, the wrap layer's behaviour is
// orthogonal to the inner ITB nonce size, so the matrix's pass /
// fail outcome is unaffected. The remaining config knobs match the
// Go-side defaults.

void apply_global_knobs() {
    itb::set_nonce_bits(128);
    itb::set_barrier_fill(4);
    itb::set_bit_soup(1);
    itb::set_lock_soup(1);
}

itb::Encryptor make_easy_encryptor(bool with_mac, int key_bits) {
    itb::Encryptor enc{
        "areion512", key_bits,
        with_mac ? "hmac-blake3" : "",
        1};
    enc.set_nonce_bits(128);
    enc.set_barrier_fill(4);
    enc.set_bit_soup(1);
    enc.set_lock_soup(1);
    return enc;
}

std::vector<itb::Seed> make_seeds_512(int n, int key_bits) {
    std::vector<itb::Seed> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        out.emplace_back("areion512", key_bits);
    }
    return out;
}

// In-memory write sink + read source for the StreamSink / StreamSource
// callbacks used by Encryptor::stream_encrypt_auth.
struct InMemoryReader {
    const std::vector<std::uint8_t>* data;
    std::size_t pos{0};
    std::size_t operator()(std::uint8_t* buf, std::size_t cap) {
        std::size_t avail = data->size() - pos;
        std::size_t take = (cap < avail) ? cap : avail;
        if (take > 0) {
            std::memcpy(buf, data->data() + pos, take);
            pos += take;
        }
        return take;
    }
};

void put_u32_le(std::uint8_t* dst, std::uint32_t v) {
    dst[0] = static_cast<std::uint8_t>(v & 0xFFu);
    dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    dst[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    dst[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
}

std::uint32_t get_u32_le(const std::uint8_t* src) {
    return static_cast<std::uint32_t>(src[0])
         | (static_cast<std::uint32_t>(src[1]) << 8)
         | (static_cast<std::uint32_t>(src[2]) << 16)
         | (static_cast<std::uint32_t>(src[3]) << 24);
}

// ----- 1. aead-easy-io ---------------------------------------------
// Sender uses Encryptor::stream_encrypt_auth backed by an in-memory
// collector; the entire emitted bytestream gets wrapped end-to-end
// through one WrapStreamWriter session. Receiver reverses with
// UnwrapStreamReader feeding the inner-stream decoder.
RunResult run_aead_easy_io(itb::wrapper::Cipher cipher,
                           const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        auto enc = make_easy_encryptor(true, 1024);

        std::vector<std::uint8_t> inner;
        InMemoryReader src{&plaintext, 0};
        enc.stream_encrypt_auth(
            std::ref(src),
            [&inner](const std::uint8_t* b, std::size_t n) {
                inner.insert(inner.end(), b, b + n);
            },
            kStreamChunkSize);

        auto outer_key = itb::wrapper::generate_key(cipher);

        // Wrap inner bytes through one keystream session. Wire is
        // `nonce || ks-XOR(inner)`.
        itb::wrapper::WrapStreamWriter ww{cipher, outer_key.data(), outer_key.size()};
        std::vector<std::uint8_t> wire;
        wire.reserve(ww.nonce().size() + inner.size());
        wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
        auto inner_xor = ww.update(inner.data(), inner.size());
        wire.insert(wire.end(), inner_xor.begin(), inner_xor.end());

        // Receiver — strip nonce, unwrap body, decrypt.
        const std::size_t nlen = ww.nonce().size();
        itb::wrapper::UnwrapStreamReader ur{cipher,
                                            outer_key.data(), outer_key.size(),
                                            wire.data(), nlen};
        auto inner_recovered = ur.update(wire.data() + nlen,
                                         wire.size() - nlen);

        std::vector<std::uint8_t> pt_out;
        InMemoryReader src2{&inner_recovered, 0};
        enc.stream_decrypt_auth(
            std::ref(src2),
            [&pt_out](const std::uint8_t* b, std::size_t n) {
                pt_out.insert(pt_out.end(), b, b + n);
            },
            kStreamChunkSize);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt_out);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 2. aead-lowlevel-io ------------------------------------------
RunResult run_aead_lowlevel_io(itb::wrapper::Cipher cipher,
                               const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        apply_global_knobs();
        auto seeds = make_seeds_512(3, 1024);
        auto mac_key = read_csprng(32);
        itb::Mac mac{"hmac-blake3", mac_key};

        std::vector<std::uint8_t> inner;
        InMemoryReader src{&plaintext, 0};
        itb::encrypt_stream_auth(
            seeds[0], seeds[1], seeds[2], mac,
            std::ref(src),
            [&inner](const std::uint8_t* b, std::size_t n) {
                inner.insert(inner.end(), b, b + n);
            },
            kStreamChunkSize);

        auto outer_key = itb::wrapper::generate_key(cipher);

        itb::wrapper::WrapStreamWriter ww{cipher, outer_key.data(), outer_key.size()};
        std::vector<std::uint8_t> wire;
        wire.reserve(ww.nonce().size() + inner.size());
        wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
        auto inner_xor = ww.update(inner.data(), inner.size());
        wire.insert(wire.end(), inner_xor.begin(), inner_xor.end());

        const std::size_t nlen2 = ww.nonce().size();
        itb::wrapper::UnwrapStreamReader ur{cipher,
                                            outer_key.data(), outer_key.size(),
                                            wire.data(), nlen2};
        auto inner_recovered = ur.update(wire.data() + nlen2,
                                         wire.size() - nlen2);

        std::vector<std::uint8_t> pt_out;
        InMemoryReader src2{&inner_recovered, 0};
        itb::decrypt_stream_auth(
            seeds[0], seeds[1], seeds[2], mac,
            std::ref(src2),
            [&pt_out](const std::uint8_t* b, std::size_t n) {
                pt_out.insert(pt_out.end(), b, b + n);
            },
            kStreamChunkSize);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt_out);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 3. noaead-easy-userloop --------------------------------------
RunResult run_noaead_easy_userloop(itb::wrapper::Cipher cipher,
                                   const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        auto enc = make_easy_encryptor(false, 1024);
        auto outer_key = itb::wrapper::generate_key(cipher);

        // Sender — wrap-writer accumulating into `wire`.
        std::vector<std::uint8_t> wire;
        wire.reserve(plaintext.size() + 256);
        itb::wrapper::WrapStreamWriter ww{cipher, outer_key.data(), outer_key.size()};
        wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());

        for (std::size_t off = 0; off < plaintext.size(); off += kStreamChunkSize) {
            std::size_t take = plaintext.size() - off;
            if (take > kStreamChunkSize) take = kStreamChunkSize;
            auto ct = enc.encrypt(plaintext.data() + off, take);
            std::uint8_t hdr[4];
            put_u32_le(hdr, static_cast<std::uint32_t>(ct.size()));
            auto hdr_xor = ww.update(hdr, 4);
            wire.insert(wire.end(), hdr_xor.begin(), hdr_xor.end());
            auto ct_xor = ww.update(ct.data(), ct.size());
            wire.insert(wire.end(), ct_xor.begin(), ct_xor.end());
        }

        // Receiver — read u32_LE length then body through the unwrap-
        // reader, looping until EOF.
        const std::size_t nlen = ww.nonce().size();
        if (wire.size() < nlen) {
            throw std::runtime_error("wire shorter than nonce");
        }
        itb::wrapper::UnwrapStreamReader ur{cipher,
                                            outer_key.data(), outer_key.size(),
                                            wire.data(), nlen};

        std::vector<std::uint8_t> pt_out;
        std::size_t off = nlen;
        while (off < wire.size()) {
            if (off + 4 > wire.size()) {
                throw std::runtime_error("truncated length prefix");
            }
            auto hdr = ur.update(wire.data() + off, 4);
            off += 4;
            auto clen = get_u32_le(hdr.data());
            if (off + clen > wire.size()) {
                throw std::runtime_error("truncated chunk body");
            }
            auto ct = ur.update(wire.data() + off, clen);
            off += clen;
            auto pt = enc.decrypt(ct);
            pt_out.insert(pt_out.end(), pt.begin(), pt.end());
        }

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt_out);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 4. noaead-lowlevel-userloop ----------------------------------
RunResult run_noaead_lowlevel_userloop(itb::wrapper::Cipher cipher,
                                       const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        apply_global_knobs();
        auto seeds = make_seeds_512(3, 1024);
        auto outer_key = itb::wrapper::generate_key(cipher);

        std::vector<std::uint8_t> wire;
        wire.reserve(plaintext.size() + 256);
        itb::wrapper::WrapStreamWriter ww{cipher, outer_key.data(), outer_key.size()};
        wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());

        for (std::size_t off = 0; off < plaintext.size(); off += kStreamChunkSize) {
            std::size_t take = plaintext.size() - off;
            if (take > kStreamChunkSize) take = kStreamChunkSize;
            auto ct = itb::encrypt(seeds[0], seeds[1], seeds[2],
                                   plaintext.data() + off, take);
            std::uint8_t hdr[4];
            put_u32_le(hdr, static_cast<std::uint32_t>(ct.size()));
            auto hdr_xor = ww.update(hdr, 4);
            wire.insert(wire.end(), hdr_xor.begin(), hdr_xor.end());
            auto ct_xor = ww.update(ct.data(), ct.size());
            wire.insert(wire.end(), ct_xor.begin(), ct_xor.end());
        }

        const std::size_t nlen = ww.nonce().size();
        if (wire.size() < nlen) {
            throw std::runtime_error("wire shorter than nonce");
        }
        itb::wrapper::UnwrapStreamReader ur{cipher,
                                            outer_key.data(), outer_key.size(),
                                            wire.data(), nlen};

        std::vector<std::uint8_t> pt_out;
        std::size_t off = nlen;
        while (off < wire.size()) {
            if (off + 4 > wire.size()) {
                throw std::runtime_error("truncated length prefix");
            }
            auto hdr = ur.update(wire.data() + off, 4);
            off += 4;
            auto clen = get_u32_le(hdr.data());
            if (off + clen > wire.size()) {
                throw std::runtime_error("truncated chunk body");
            }
            auto ct = ur.update(wire.data() + off, clen);
            off += clen;
            auto pt = itb::decrypt(seeds[0], seeds[1], seeds[2], ct);
            pt_out.insert(pt_out.end(), pt.begin(), pt.end());
        }

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt_out);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 5. message-easy-nomac ----------------------------------------
//
// Default eitb path mirrors tools/eitb/main.go: wrap_in_place (mutates
// the ciphertext buffer in place) + unwrap_in_place. The commented
// `wrap` / `unwrap` alternatives respect immutability of `encrypted` /
// `wire` at the cost of an extra allocation per call.
RunResult run_message_easy_nomac(itb::wrapper::Cipher cipher,
                                 const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        auto enc = make_easy_encryptor(false, 2048);
        auto encrypted = enc.encrypt(plaintext);
        auto outer_key = itb::wrapper::generate_key(cipher);

        // Wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
        //   auto wire = itb::wrapper::wrap(cipher,
        //                                  outer_key.data(), outer_key.size(),
        //                                  encrypted.data(), encrypted.size());
        //
        // wrap_in_place mutates `encrypted` and returns the per-stream
        // nonce; the caller composes `nonce || mutated-ct` into the
        // wire (one extra memcpy below). Zero allocation steady state.
        auto nonce = itb::wrapper::wrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            encrypted.data(), encrypted.size());

        std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
        std::copy(nonce.begin(), nonce.end(), wire.begin());
        std::copy(encrypted.begin(), encrypted.end(),
                  wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

        // Unwrap respects immutability of `wire`:
        //   auto recovered = itb::wrapper::unwrap(cipher,
        //                                         outer_key.data(), outer_key.size(),
        //                                         wire.data(), wire.size());
        auto body = itb::wrapper::unwrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            wire.data(), wire.size());

        std::vector<std::uint8_t> body_vec(body.first, body.first + body.second);
        auto pt = enc.decrypt(body_vec);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 6. message-easy-auth -----------------------------------------
RunResult run_message_easy_auth(itb::wrapper::Cipher cipher,
                                const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        auto enc = make_easy_encryptor(true, 2048);
        auto encrypted = enc.encrypt_auth(plaintext);
        auto outer_key = itb::wrapper::generate_key(cipher);

        // See message-easy-nomac for the immutable-input alternative
        // (wrap / unwrap with separately-allocated buffers).
        auto nonce = itb::wrapper::wrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            encrypted.data(), encrypted.size());

        std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
        std::copy(nonce.begin(), nonce.end(), wire.begin());
        std::copy(encrypted.begin(), encrypted.end(),
                  wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

        auto body = itb::wrapper::unwrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            wire.data(), wire.size());

        std::vector<std::uint8_t> body_vec(body.first, body.first + body.second);
        auto pt = enc.decrypt_auth(body_vec);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 7. message-lowlevel-nomac ------------------------------------
RunResult run_message_lowlevel_nomac(itb::wrapper::Cipher cipher,
                                     const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        apply_global_knobs();
        auto seeds = make_seeds_512(3, 2048);
        auto encrypted = itb::encrypt(seeds[0], seeds[1], seeds[2], plaintext);
        auto outer_key = itb::wrapper::generate_key(cipher);

        auto nonce = itb::wrapper::wrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            encrypted.data(), encrypted.size());

        std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
        std::copy(nonce.begin(), nonce.end(), wire.begin());
        std::copy(encrypted.begin(), encrypted.end(),
                  wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

        auto body = itb::wrapper::unwrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            wire.data(), wire.size());

        std::vector<std::uint8_t> body_vec(body.first, body.first + body.second);
        auto pt = itb::decrypt(seeds[0], seeds[1], seeds[2], body_vec);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- 8. message-lowlevel-auth -------------------------------------
RunResult run_message_lowlevel_auth(itb::wrapper::Cipher cipher,
                                    const std::vector<std::uint8_t>& plaintext) {
    RunResult r;
    try {
        apply_global_knobs();
        auto seeds = make_seeds_512(3, 2048);
        auto mac_key = read_csprng(32);
        itb::Mac mac{"hmac-blake3", mac_key};

        auto encrypted = itb::encrypt_auth(
            seeds[0], seeds[1], seeds[2], mac, plaintext);
        auto outer_key = itb::wrapper::generate_key(cipher);

        auto nonce = itb::wrapper::wrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            encrypted.data(), encrypted.size());

        std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
        std::copy(nonce.begin(), nonce.end(), wire.begin());
        std::copy(encrypted.begin(), encrypted.end(),
                  wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

        auto body = itb::wrapper::unwrap_in_place(
            cipher,
            outer_key.data(), outer_key.size(),
            wire.data(), wire.size());

        std::vector<std::uint8_t> body_vec(body.first, body.first + body.second);
        auto pt = itb::decrypt_auth(seeds[0], seeds[1], seeds[2], mac, body_vec);

        r.ok = true;
        r.wire_n = wire.size();
        r.recovered = std::move(pt);
    } catch (const std::exception& e) {
        r.err_msg = e.what();
    }
    return r;
}

// ----- Driver --------------------------------------------------------

using ExampleFn = RunResult (*)(itb::wrapper::Cipher,
                                const std::vector<std::uint8_t>&);

struct Example {
    const char* name;
    const char* description;
    std::size_t payload_bytes;
    ExampleFn fn;
};

constexpr Example kExamples[] = {
    { "aead-easy-io",             "Streaming AEAD Easy (MAC Authenticated, IO-Driven)",
      kStreamBytes, run_aead_easy_io },
    { "aead-lowlevel-io",         "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)",
      kStreamBytes, run_aead_lowlevel_io },
    { "noaead-easy-userloop",     "Streaming Easy (No MAC, User-Driven Loop)",
      kStreamBytes, run_noaead_easy_userloop },
    { "noaead-lowlevel-userloop", "Streaming Low-Level (No MAC, User-Driven Loop)",
      kStreamBytes, run_noaead_lowlevel_userloop },
    { "message-easy-nomac",       "Easy: Areion-SoEM-512 (No MAC, Single Message)",
      kSingleMessageBytes, run_message_easy_nomac },
    { "message-easy-auth",        "Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
      kSingleMessageBytes, run_message_easy_auth },
    { "message-lowlevel-nomac",   "Low-Level: Areion-SoEM-512 (No MAC, Single Message)",
      kSingleMessageBytes, run_message_lowlevel_nomac },
    { "message-lowlevel-auth",    "Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
      kSingleMessageBytes, run_message_lowlevel_auth },
};

bool contains_substring(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return haystack.find(needle) != std::string_view::npos;
}

void usage(const char* prog) {
    std::fprintf(stderr,
                 "usage: %s [--example SUBSTR] [--cipher aes|chacha|siphash] [-v]\n",
                 prog);
}

} // namespace

int main(int argc, char** argv) {
    std::string example_filter;
    std::string cipher_filter;
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::string_view a{argv[i]};
        if (a == "--example" && i + 1 < argc) {
            example_filter = argv[++i];
        } else if (a == "--cipher" && i + 1 < argc) {
            cipher_filter = argv[++i];
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    try {
        itb::set_max_workers(0);
    } catch (const itb::ItbError& e) {
        std::fprintf(stderr, "set_max_workers(0) failed: %s\n", e.what());
        return 1;
    }

    int pass = 0;
    int fail = 0;
    for (const auto& ex : kExamples) {
        if (!contains_substring(ex.name, example_filter)) continue;
        for (auto cipher : kCiphers) {
            const auto cn_view = itb::wrapper::ffi_name(cipher);
            std::string cipher_name{cn_view};
            if (!cipher_filter.empty() && cipher_name != cipher_filter) continue;

            std::vector<std::uint8_t> plaintext;
            try {
                plaintext = read_csprng(ex.payload_bytes);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "csprng plaintext failed: %s\n", e.what());
                return 1;
            }
            std::uint8_t pt_digest[ITB_EITB_SHA256_DIGEST_LEN];
            itb_eitb_sha256(plaintext.data(), plaintext.size(), pt_digest);

            auto res = ex.fn(cipher, plaintext);

            bool matches = res.ok
                && res.recovered.size() == ex.payload_bytes
                && std::memcmp(res.recovered.data(), plaintext.data(),
                               ex.payload_bytes) == 0;
            const char* tag = matches ? "PASS" : "FAIL";
            if (matches) ++pass;
            else ++fail;

            std::printf("[%s] %-26s + %-8s   pt=%zu wire=%zu",
                        tag, ex.name, cipher_name.c_str(),
                        ex.payload_bytes, res.wire_n);
            if (!matches) {
                if (!res.err_msg.empty()) {
                    std::printf("  err: %s", res.err_msg.c_str());
                } else if (res.ok) {
                    std::uint8_t rcv_digest[ITB_EITB_SHA256_DIGEST_LEN];
                    if (!res.recovered.empty()) {
                        itb_eitb_sha256(res.recovered.data(),
                                        res.recovered.size(), rcv_digest);
                    } else {
                        std::memset(rcv_digest, 0, sizeof(rcv_digest));
                    }
                    std::printf("  err: plaintext hash mismatch (pt=%s rcv=%s)",
                                hex_short(pt_digest).c_str(),
                                hex_short(rcv_digest).c_str());
                }
            }
            std::printf("\n");

            if (verbose && matches) {
                std::printf("       pt sha256:  %s\n",
                            hex_full(pt_digest).c_str());
                std::uint8_t rcv_digest[ITB_EITB_SHA256_DIGEST_LEN];
                itb_eitb_sha256(res.recovered.data(), res.recovered.size(),
                                rcv_digest);
                std::printf("       rcv sha256: %s\n",
                            hex_full(rcv_digest).c_str());
            }
        }
    }

    std::printf("\n=== Summary: %d PASS, %d FAIL ===\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
