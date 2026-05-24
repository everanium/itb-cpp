// wrapper.hpp — format-deniability wrapper RAII surface for the C++
// binding.
//
// Header-only RAII facade over the C binding's `itb_wrap*` /
// `itb_unwrap*` / `itb_wrap_stream_writer_*` /
// `itb_unwrap_stream_reader_*` API. Wraps an ITB ciphertext under one
// of three outer keystream ciphers — AES-128-CTR, ChaCha20 (RFC8439),
// or SipHash-2-4 in CTR mode — so the on-wire bytes carry no
// ITB-specific format pattern. Wire format is `nonce ||
// keystream-XOR(bytestream)`, indistinguishable from any generic
// stream-cipher payload by surface pattern. ITB's content-deniability
// is unchanged; the AEAD path's integrity is unchanged. The wrap
// exists for **format-deniability ONLY** — adding a MAC at this layer
// would defeat the goal.
//
// Surface:
//
//   - `itb::wrapper::Cipher` — strongly-typed enum class selector
//     mapping to the C-binding's `itb_wrapper_cipher_t`.
//   - `itb::wrapper::ffi_name(Cipher)` — interned canonical short
//     name (`"aescmac"` / `"chacha20"` / `"siphash24"`).
//   - `itb::wrapper::key_size(Cipher)` / `nonce_size(Cipher)` — byte
//     lengths of the outer cipher's key / on-wire nonce.
//   - `itb::wrapper::generate_key(Cipher)` — fresh CSPRNG outer key.
//   - `itb::wrapper::wrap(Cipher, key, key_len, blob, blob_len)` —
//     Single Message wrap; allocates a fresh `nonce || ks-XOR(blob)` wire.
//   - `itb::wrapper::unwrap(Cipher, key, key_len, wire, wire_len)` —
//     Single Message unwrap; allocates a fresh recovered-blob buffer.
//   - `itb::wrapper::wrap_in_place(Cipher, key, key_len, blob, blob_len)` —
//     mutates `blob` in place; returns the per-stream nonce.
//   - `itb::wrapper::unwrap_in_place(Cipher, key, key_len, wire, wire_len)` —
//     mutates `wire` in place; returns a `(pointer, length)` pair over
//     the recovered body (`wire[nonce_size .. wire_len)`).
//   - `itb::wrapper::WrapStreamWriter` — RAII streaming wrap-encrypt
//     handle with `update` / `update_in_place` methods.
//   - `itb::wrapper::UnwrapStreamReader` — RAII streaming
//     unwrap-decrypt handle with `update` / `update_in_place`
//     methods.
//
// All free functions throw `itb::ItbError` on FFI failure. The
// streaming classes are move-only RAII — the destructor releases the
// underlying libitb handle via `itb_wrap_stream_writer_free` /
// `itb_unwrap_stream_reader_free`; double-free is idempotent at the
// C-binding layer.
//
// Threading. The Single Message `wrap` / `unwrap` / `wrap_in_place` /
// `unwrap_in_place` are thread-safe — each call constructs an
// outer cipher session of its own and the libitb keystream
// constructor draws a fresh CSPRNG nonce per call. The streaming
// `WrapStreamWriter` / `UnwrapStreamReader` handles are single-feeder
// — every `update` call advances the underlying keystream counter;
// concurrent `update` calls on the same handle race. Distinct
// handles run independently.
//
// Asymmetry note (no `std::iostream` adapter for Non-AEAD
// streaming). The C++ binding's existing streams.hpp surface mirrors
// the C binding's callback-driven push pattern for Streaming AEAD;
// Non-AEAD streaming is exposed only as the User-Driven Loop. The
// wrapper layer follows the same pattern: the streaming wrap-writer
// and unwrap-reader are byte-array `update` driven, not
// `std::ostream` / `std::istream` driven. Caller-side framing (e.g.
// `u32_LE` length prefixes) is written through the `update` calls so
// the framing bytes pass through the keystream XOR alongside the
// inner ITB ciphertext bodies.
//
// Public API uses `const uint8_t* + size_t` / `uint8_t* + size_t`
// pointer+length pairs throughout, so the wrapper header compiles
// against the same C++17 baseline as the rest of the C++ binding.

#pragma once

#include <itb.h>
#include <itb/errors.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace itb {
namespace wrapper {

// ---- Cipher selector ---------------------------------------------

// Strongly-typed enum class enumerating the nine supported outer
// keystream ciphers. Underlying integer values match the
// `itb_wrapper_cipher_t` enum in the C binding (and in turn match
// `wrapper.CipherNames` in the Go-side wrapper package), so a static
// cast across the boundary is safe.
enum class Cipher : int {
    Aes128Ctr  = ITB_WRAPPER_CIPHER_AES_128_CTR,
    ChaCha20   = ITB_WRAPPER_CIPHER_CHACHA20,
    SipHash24  = ITB_WRAPPER_CIPHER_SIPHASH24,
    Areion256  = ITB_WRAPPER_CIPHER_AREION_256,
    Areion512  = ITB_WRAPPER_CIPHER_AREION_512,
    Blake2b256 = ITB_WRAPPER_CIPHER_BLAKE2B_256,
    Blake2b512 = ITB_WRAPPER_CIPHER_BLAKE2B_512,
    Blake2s    = ITB_WRAPPER_CIPHER_BLAKE2S,
    Blake3     = ITB_WRAPPER_CIPHER_BLAKE3,
};

// Returns the canonical short name of the named outer cipher
// (`"aescmac"` / `"chacha20"` / `"siphash24"` / `"areion256"` /
// `"areion512"` / `"blake2b256"` / `"blake2b512"` / `"blake2s"` /
// `"blake3"`) as a non-owning view over the process-lifetime interned C
// string. The view stays valid for the life of the process; callers
// MUST NOT free the underlying buffer.
inline std::string_view ffi_name(Cipher cipher) noexcept {
    const char* p = itb_wrapper_cipher_name(
        static_cast<itb_wrapper_cipher_t>(cipher));
    if (p == nullptr) {
        return std::string_view{};
    }
    return std::string_view{p};
}

// Returns the byte length of the keystream-cipher key for the named
// outer cipher: 16 for AES-128-CTR / SipHash-CTR; 32 for ChaCha20 /
// Areion-SoEM-256 / BLAKE2b-256 / BLAKE2b-512 / BLAKE2s / BLAKE3; 64 for
// Areion-SoEM-512. Throws `ItbError(STATUS_BAD_INPUT)` on an unknown
// cipher value.
inline std::size_t key_size(Cipher cipher) {
    std::size_t out = 0;
    detail::check(itb_wrapper_key_size(
        static_cast<itb_wrapper_cipher_t>(cipher), &out));
    return out;
}

// Returns the on-wire nonce length the named outer cipher emits per
// stream: 12 for ChaCha20; 16 for every other outer cipher (AES-128-CTR /
// SipHash-CTR / Areion-SoEM-256 / Areion-SoEM-512 / BLAKE2b-256 /
// BLAKE2b-512 / BLAKE2s / BLAKE3). Throws `ItbError(STATUS_BAD_INPUT)`
// on an unknown cipher value.
inline std::size_t nonce_size(Cipher cipher) {
    std::size_t out = 0;
    detail::check(itb_wrapper_nonce_size(
        static_cast<itb_wrapper_cipher_t>(cipher), &out));
    return out;
}

// Generates a fresh CSPRNG outer cipher key of the size required by
// `cipher` (via `key_size`). Reads `/dev/urandom` on POSIX hosts via
// the C binding's `itb_wrapper_generate_key`.
//
// On failure throws `ItbError(STATUS_INTERNAL)` with the libitb
// last-error message attached.
inline std::vector<std::uint8_t> generate_key(Cipher cipher) {
    std::uint8_t* buf = nullptr;
    std::size_t len = 0;
    detail::check(itb_wrapper_generate_key(
        static_cast<itb_wrapper_cipher_t>(cipher), &buf, &len));
    std::vector<std::uint8_t> out(buf, buf + len);
    itb_buffer_free(buf);
    return out;
}

// Deterministically derives the outer cipher key for `cipher` from a
// caller-supplied master secret (e.g. an ML-KEM shared secret). The
// result is a deterministic function of `(cipher, master)`, so both
// endpoints derive the same key from a shared master. `master` must be
// at least 32 bytes (the wrapper's uniform security floor); the returned
// buffer has length `key_size(cipher)`.
//
// On failure (unknown cipher, too-short master) throws `ItbError`
// carrying the libitb last-error message.
inline std::vector<std::uint8_t> derive_key(Cipher cipher,
                                            const std::uint8_t* master,
                                            std::size_t master_len) {
    std::uint8_t* buf = nullptr;
    std::size_t len = 0;
    const std::uint8_t* master_ptr = (master_len == 0) ? nullptr : master;
    detail::check(itb_wrapper_derive_key(
        static_cast<itb_wrapper_cipher_t>(cipher),
        master_ptr, master_len,
        &buf, &len));
    std::vector<std::uint8_t> out(buf, buf + len);
    itb_buffer_free(buf);
    return out;
}

// ---- Single Message wrap / unwrap -----------------------------------

// Single Message wrap. Seals `blob` under `cipher` with a fresh per-call
// CSPRNG nonce; returns a freshly-allocated buffer holding `nonce ||
// keystream-XOR(blob)`. Empty blob is permitted — the wire becomes
// `nonce` alone.
inline std::vector<std::uint8_t> wrap(Cipher cipher,
                                      const std::uint8_t* key,
                                      std::size_t key_len,
                                      const std::uint8_t* blob,
                                      std::size_t blob_len) {
    std::uint8_t* buf = nullptr;
    std::size_t len = 0;
    const std::uint8_t* blob_ptr = (blob_len == 0) ? nullptr : blob;
    detail::check(itb_wrap(
        static_cast<itb_wrapper_cipher_t>(cipher),
        key, key_len,
        blob_ptr, blob_len,
        &buf, &len));
    std::vector<std::uint8_t> out(buf, buf + len);
    itb_buffer_free(buf);
    return out;
}

// Single Message unwrap. Reads the leading `nonce_size(cipher)` bytes of
// `wire` as the per-stream nonce, XOR-decrypts the remainder under
// `(key, nonce)`, and returns a freshly-allocated buffer holding the
// recovered blob. Throws `ItbError(STATUS_BAD_INPUT)` when `wire`
// is shorter than the nonce.
inline std::vector<std::uint8_t> unwrap(Cipher cipher,
                                        const std::uint8_t* key,
                                        std::size_t key_len,
                                        const std::uint8_t* wire,
                                        std::size_t wire_len) {
    std::uint8_t* buf = nullptr;
    std::size_t len = 0;
    const std::uint8_t* wire_ptr = (wire_len == 0) ? nullptr : wire;
    detail::check(itb_unwrap(
        static_cast<itb_wrapper_cipher_t>(cipher),
        key, key_len,
        wire_ptr, wire_len,
        &buf, &len));
    std::vector<std::uint8_t> out(buf, buf + len);
    itb_buffer_free(buf);
    return out;
}

// In-place Single Message wrap. XORs `blob` under a freshly drawn per-
// call CSPRNG nonce; the returned vector holds the per-stream nonce
// bytes. The caller composes `nonce || mutated-blob` to produce the
// wire (or emits the two pieces separately).
//
// `blob` is **MUTATED** in place. Use `wrap` when the caller's
// plaintext must be preserved.
inline std::vector<std::uint8_t> wrap_in_place(
    Cipher cipher,
    const std::uint8_t* key,
    std::size_t key_len,
    std::uint8_t* blob,
    std::size_t blob_len) {
    std::size_t nlen = nonce_size(cipher);
    std::vector<std::uint8_t> nonce(nlen, 0);
    std::uint8_t* blob_ptr = (blob_len == 0) ? nullptr : blob;
    detail::check(itb_wrap_in_place(
        static_cast<itb_wrapper_cipher_t>(cipher),
        key, key_len,
        blob_ptr, blob_len,
        nonce.data(), nonce.size()));
    return nonce;
}

// In-place Single Message unwrap. Strips the leading `nonce_size(cipher)`
// bytes from `wire` and XOR-decrypts the remainder in place. Returns
// a `(pointer, length)` pair over the decrypted body
// (`wire[nonce_size .. wire_len)`). The leading nonce prefix is left
// unchanged. `wire` is **MUTATED** in place.
//
// The returned pointer is a view into `wire`; the caller MUST keep
// `wire`'s storage alive while reading through the pointer.
//
// Throws `ItbError(STATUS_BAD_INPUT)` when `wire_len` is shorter than
// the nonce.
inline std::pair<std::uint8_t*, std::size_t> unwrap_in_place(
    Cipher cipher,
    const std::uint8_t* key,
    std::size_t key_len,
    std::uint8_t* wire,
    std::size_t wire_len) {
    std::size_t nlen = nonce_size(cipher);
    std::uint8_t* wire_ptr = (wire_len == 0) ? nullptr : wire;
    detail::check(itb_unwrap_in_place(
        static_cast<itb_wrapper_cipher_t>(cipher),
        key, key_len,
        wire_ptr, wire_len));
    if (wire_len < nlen) {
        // Defensive: itb_unwrap_in_place rejected the call already.
        return std::pair<std::uint8_t*, std::size_t>{nullptr, 0};
    }
    return std::pair<std::uint8_t*, std::size_t>{
        wire + nlen, wire_len - nlen};
}

// ---- Streaming wrap-encrypt handle -------------------------------

// Move-only RAII facade over the C binding's
// `itb_wrap_stream_writer_t`. The constructor draws a fresh CSPRNG
// nonce, opens a libitb wrap-stream session keyed by `(cipher, key,
// nonce)`, and stashes the nonce bytes inside the instance. Caller
// reads the nonce via `nonce()` and emits it once at stream start
// (typically as the wire prefix) so the matching `UnwrapStreamReader`
// can be constructed against it.
//
// Subsequent `update` calls XOR caller bytes through the keystream;
// the keystream counter advances monotonically across all bytes fed
// into the session.
class WrapStreamWriter {
public:
    // Allocate a fresh streaming wrap-encrypt handle for the named
    // outer cipher under the caller-supplied key. Draws a CSPRNG
    // nonce internally; reachable via `nonce()`.
    WrapStreamWriter(Cipher cipher,
                     const std::uint8_t* key,
                     std::size_t key_len)
        : cipher_{cipher},
          nonce_(nonce_size(cipher), 0),
          handle_{nullptr} {
        detail::check(itb_wrap_stream_writer_new(
            static_cast<itb_wrapper_cipher_t>(cipher),
            key, key_len,
            nonce_.data(), nonce_.size(),
            &handle_));
    }

    WrapStreamWriter(const WrapStreamWriter&) = delete;
    WrapStreamWriter& operator=(const WrapStreamWriter&) = delete;

    WrapStreamWriter(WrapStreamWriter&& other) noexcept
        : cipher_{other.cipher_},
          nonce_{std::move(other.nonce_)},
          handle_{other.handle_} {
        other.handle_ = nullptr;
    }

    WrapStreamWriter& operator=(WrapStreamWriter&& other) noexcept {
        if (this != &other) {
            release();
            cipher_ = other.cipher_;
            nonce_ = std::move(other.nonce_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~WrapStreamWriter() noexcept { release(); }

    // The per-stream nonce drawn at construction time. Emit once at
    // stream start so the receiver can construct the matching
    // `UnwrapStreamReader`.
    const std::vector<std::uint8_t>& nonce() const noexcept { return nonce_; }

    // The cipher selector this writer was constructed with.
    Cipher cipher() const noexcept { return cipher_; }

    // XOR-encrypt `src_len` bytes at `src` through the keystream into a
    // freshly-allocated buffer of the same length. The keystream
    // counter advances by `src_len` bytes. Empty input is a no-op and
    // returns an empty vector.
    std::vector<std::uint8_t> update(const std::uint8_t* src,
                                     std::size_t src_len) {
        std::vector<std::uint8_t> out(src_len, 0);
        if (src_len == 0) {
            return out;
        }
        detail::check(itb_wrap_stream_writer_update(
            handle_,
            src, src_len,
            out.data(), out.size()));
        return out;
    }

    // XOR-encrypt `buf_len` bytes at `buf` in place. The keystream
    // counter advances by `buf_len` bytes. Empty input is a no-op.
    void update_in_place(std::uint8_t* buf, std::size_t buf_len) {
        if (buf_len == 0) {
            return;
        }
        detail::check(itb_wrap_stream_writer_update(
            handle_,
            buf, buf_len,
            buf, buf_len));
    }

private:
    void release() noexcept {
        if (handle_ != nullptr) {
            itb_wrap_stream_writer_free(handle_);
            handle_ = nullptr;
        }
    }

    Cipher cipher_;
    std::vector<std::uint8_t> nonce_;
    itb_wrap_stream_writer_t* handle_;
};

// ---- Streaming unwrap-decrypt handle -----------------------------

// Move-only RAII facade over the C binding's
// `itb_unwrap_stream_reader_t`. The constructor opens a libitb
// wrap-stream session keyed by `(cipher, key, wire_nonce)`;
// subsequent `update` calls XOR caller wire bytes back to plaintext
// under the keystream advancing from counter zero.
//
// `wire_nonce_len` must equal `nonce_size(cipher)` or the constructor
// throws `ItbError(STATUS_BAD_INPUT)`.
class UnwrapStreamReader {
public:
    UnwrapStreamReader(Cipher cipher,
                       const std::uint8_t* key,
                       std::size_t key_len,
                       const std::uint8_t* wire_nonce,
                       std::size_t wire_nonce_len)
        : cipher_{cipher}, handle_{nullptr} {
        detail::check(itb_unwrap_stream_reader_new(
            static_cast<itb_wrapper_cipher_t>(cipher),
            key, key_len,
            wire_nonce, wire_nonce_len,
            &handle_));
    }

    UnwrapStreamReader(const UnwrapStreamReader&) = delete;
    UnwrapStreamReader& operator=(const UnwrapStreamReader&) = delete;

    UnwrapStreamReader(UnwrapStreamReader&& other) noexcept
        : cipher_{other.cipher_}, handle_{other.handle_} {
        other.handle_ = nullptr;
    }

    UnwrapStreamReader& operator=(UnwrapStreamReader&& other) noexcept {
        if (this != &other) {
            release();
            cipher_ = other.cipher_;
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~UnwrapStreamReader() noexcept { release(); }

    Cipher cipher() const noexcept { return cipher_; }

    // XOR-decrypt `src_len` bytes at `src` through the keystream into
    // a freshly-allocated buffer of the same length. Empty input is a
    // no-op and returns an empty vector.
    std::vector<std::uint8_t> update(const std::uint8_t* src,
                                     std::size_t src_len) {
        std::vector<std::uint8_t> out(src_len, 0);
        if (src_len == 0) {
            return out;
        }
        detail::check(itb_unwrap_stream_reader_update(
            handle_,
            src, src_len,
            out.data(), out.size()));
        return out;
    }

    // XOR-decrypt `buf_len` bytes at `buf` in place. Empty input is a
    // no-op.
    void update_in_place(std::uint8_t* buf, std::size_t buf_len) {
        if (buf_len == 0) {
            return;
        }
        detail::check(itb_unwrap_stream_reader_update(
            handle_,
            buf, buf_len,
            buf, buf_len));
    }

private:
    void release() noexcept {
        if (handle_ != nullptr) {
            itb_unwrap_stream_reader_free(handle_);
            handle_ = nullptr;
        }
    }

    Cipher cipher_;
    itb_unwrap_stream_reader_t* handle_;
};

} // namespace wrapper
} // namespace itb
