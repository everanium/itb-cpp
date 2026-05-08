// encryptor.hpp — Easy Mode RAII wrapper around `itb_encryptor_t`.
//
// Move-only RAII facade over the C binding's Easy Mode encryptor. The
// wrapper owns the underlying `itb_encryptor_t*` and releases it on
// destruction via `itb_encryptor_close` followed by
// `itb_encryptor_free` (idempotent ordering enforced by the C
// binding).
//
// Constructors. Mixed-primitive variants are exposed as static
// factories `Encryptor::Mixed` / `Encryptor::Mixed3`, matching the
// C# binding's overload-with-numeric-suffix convention:
//
//     itb::Encryptor e1{"blake3", 1024, "hmac-blake3", 1};
//     auto e2 = itb::Encryptor::Mixed("blake3", "blake2s",
//                                     "blake2b256", "" /*no lockSeed*/,
//                                     1024, "hmac-blake3");
//     auto e3 = itb::Encryptor::Mixed3("blake3",
//                                      "blake2s", "blake2b256", "blake3",
//                                      "blake2s", "blake2b256", "blake3",
//                                      "areion256", 1024, "hmac-blake3");
//
// Default-MAC override: an empty `mac` argument forwards as
// `nullptr` to the underlying C binding, which substitutes
// `"hmac-blake3"` (the lightest authenticated-mode overhead among
// the three shipping MACs).
//
// Closed-state preflight on every public method: after `close()`
// the encryptor's `_closed` flag is set, and subsequent calls
// raise `ItbError(STATUS_EASY_CLOSED)` directly without round-
// tripping libitb.
//
// Threading. A single `Encryptor` instance is NOT safe for concurrent
// use — cipher methods, setters, close, and import all mutate the
// per-instance output cache and configuration without internal
// locking. Distinct instances run independently against the libitb
// worker pool. Process-wide setters in <itb/library.hpp> are atomic
// per call but are NOT logically race-free — mutating any of them
// while a cipher call is in flight on any thread corrupts that
// running operation, because the cipher snapshots its configuration
// at call entry. Treat the global knobs as set-once-at-startup.

#pragma once

#include <itb.h>
#include <itb/errors.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace itb {

namespace detail {

// Defensive runtime guard for two-call probe sites: asserts that the
// post-second-call visible length does not exceed the buffer capacity
// the binding allocated. The C-binding contract guarantees `visible
// <= cap - 1` after the read leg; surfacing a future-regression
// violation as `ItbError(STATUS_INTERNAL)` converts a silent
// mask into a loud fail. Used at peek_config / read_two_call_string
// / last_mismatch_field probe sites.
inline void expect_visible_le_cap(std::size_t visible, std::size_t cap) {
    if (visible + 1 > cap) {
        throw ItbError{status::kInternal,
                       "two-call probe contract violation: "
                       "post-call visible exceeds allocated capacity"};
    }
}

// Reads a NUL-stripped string written by an `itb_*` two-call probe
// entry point. The closure `call` takes `(buf, cap, *out_len)` and
// returns the status code.
//
// Contract: `*out_len` reports the **visible** (NUL-stripped) length
// on every code path; the read call writes `visible + 1` bytes total
// (NUL terminator included) and requires `cap >= visible + 1`. The
// probe with `cap = 0` returns `BUFFER_TOO_SMALL` plus `*out_len =
// visible`, while empty strings short-circuit with `*out_len = 0` +
// `OK`.
template <class Fn>
inline std::string read_two_call_string(Fn call) {
    std::size_t visible = 0;
    int rc = call(nullptr, 0, &visible);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        throw_from_status(rc);
    }
    if (visible == 0) {
        return std::string{};
    }
    std::string buf(visible + 1, '\0');
    rc = call(buf.data(), buf.size(), &visible);
    if (rc != ITB_OK) {
        throw_from_status(rc);
    }
    expect_visible_le_cap(visible, buf.size());
    buf.resize(visible);
    return buf;
}

// Owning holder for a NUL-terminated copy of a `std::string_view`
// argument. The C ABI takes `const char*` parameters that MUST be
// NUL-terminated; a raw `string_view::data()` may point into a
// non-NUL-terminated buffer (substring view, slice into a larger
// string, view over a `std::vector<char>`), and the C side's
// `strlen` would walk past the visible bytes. This holder
// materialises a NUL-terminated `std::string` from the source view
// and exposes its `c_str()`; the empty view forwards as `nullptr`
// (lets the C binding's default-MAC override fire on its own).
//
// Usage at every Encryptor / Mixed / Mixed3 ctor site:
//
//     NulView prim{primitive};
//     NulView mac{mac_name};
//     int rc = itb_encryptor_new(prim.c_str(), key_bits, mac.c_str(), ...);
//
// The holder must outlive the FFI call (stack-scope construction at
// the call site is the canonical pattern).
class NulView {
public:
    explicit NulView(std::string_view s) : empty_{s.empty()} {
        if (!empty_) {
            storage_.assign(s);
        }
    }

    const char* c_str() const noexcept {
        return empty_ ? nullptr : storage_.c_str();
    }

private:
    bool empty_;
    std::string storage_;
};

// Converts a malloc'd output buffer returned by libitb (`**out_buf`)
// into a freshly-allocated `std::vector<uint8_t>` owned by the caller,
// then frees the libitb-side buffer via `itb_buffer_free`. The double
// allocation is the documented FFI overhead for the C++ binding —
// alternative zero-copy approaches surface a custom-deleter
// `unique_ptr<uint8_t[]>` which is harder to interoperate with the
// rest of the C++ ecosystem (`std::vector` / `std::string` /
// `std::span` consumers).
//
// A small RAII guard frees the C-side buffer if the vector copy
// throws `std::bad_alloc` between construction and return. Without
// the guard, OOM during the duplicating allocation would leak the
// libitb-owned pointer for the lifetime of the process.
inline std::vector<std::uint8_t> consume_buffer(std::uint8_t* buf,
                                                std::size_t len) {
    if (buf == nullptr) {
        return {};
    }
    struct CSideBuffer {
        std::uint8_t* p;
        ~CSideBuffer() noexcept {
            if (p != nullptr) {
                itb_buffer_free(p);
            }
        }
    } guard{buf};
    return std::vector<std::uint8_t>(buf, buf + len);
}

} // namespace detail

// ---- peek_config free function -----------------------------------

// Parses a state blob's metadata (`primitive`, `key_bits`, `mode`,
// `mac_name`) without performing full validation. Useful when a
// caller wants to inspect a saved blob before constructing a
// matching encryptor.
//
// Surfaces `ItbError(STATUS_EASY_MALFORMED)` on JSON parse failure /
// kind mismatch / too-new version / unknown mode value. peek_config
// conflates the too-new-version case with the malformed case;
// `Encryptor::import_state` is the only path that surfaces
// `STATUS_EASY_VERSION_TOO_NEW` distinctly.
struct PeekedConfig {
    std::string primitive;
    int key_bits = 0;
    int mode = 0;
    std::string mac_name;
};

inline PeekedConfig peek_config(const std::uint8_t* blob, std::size_t len) {
    std::size_t prim_visible = 0;
    std::size_t mac_visible = 0;
    int kb = 0;
    int mode = 0;
    int rc = itb_easy_peek_config(blob, len,
                                  nullptr, 0, &prim_visible,
                                  &kb, &mode,
                                  nullptr, 0, &mac_visible);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        detail::throw_from_status(rc);
    }
    PeekedConfig out;

    // C-binding contract: probe sets *out_len to the visible
    // (NUL-stripped) length; the read call writes `visible + 1` bytes
    // total and requires `cap >= visible + 1`.
    if (prim_visible > 0) {
        out.primitive.assign(prim_visible + 1, '\0');
    }
    if (mac_visible > 0) {
        out.mac_name.assign(mac_visible + 1, '\0');
    }
    rc = itb_easy_peek_config(
        blob, len,
        out.primitive.empty() ? nullptr : out.primitive.data(),
        out.primitive.size(), &prim_visible,
        &kb, &mode,
        out.mac_name.empty() ? nullptr : out.mac_name.data(),
        out.mac_name.size(), &mac_visible);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    out.key_bits = kb;
    out.mode = mode;
    if (!out.primitive.empty()) {
        detail::expect_visible_le_cap(prim_visible, out.primitive.size());
        out.primitive.resize(prim_visible);
    }
    if (!out.mac_name.empty()) {
        detail::expect_visible_le_cap(mac_visible, out.mac_name.size());
        out.mac_name.resize(mac_visible);
    }
    return out;
}

inline PeekedConfig peek_config(const std::vector<std::uint8_t>& blob) {
    return peek_config(blob.data(), blob.size());
}

// ---- Encryptor class ---------------------------------------------

class Encryptor {
public:
    // Construct a single-primitive encryptor. Empty `primitive` /
    // `mac` and `key_bits = 0` select the libitb defaults
    // (`"areion512"`, `1024`, `"hmac-blake3"`); `mode` is `1`
    // (Single Ouroboros) or `3` (Triple Ouroboros). Other mode
    // values surface as `ItbError(STATUS_BAD_INPUT)` from libitb.
    Encryptor(std::string_view primitive, int key_bits,
              std::string_view mac, int mode) {
        detail::NulView prim_nv{primitive};
        detail::NulView mac_nv{mac};
        int rc = itb_encryptor_new(prim_nv.c_str(),
                                   key_bits,
                                   mac_nv.c_str(),
                                   mode,
                                   &handle_);
        if (rc != ITB_OK) {
            handle_ = nullptr;
            detail::throw_from_status(rc);
        }
    }

    // Mixed-primitive Single-Ouroboros constructor — independent
    // primitive choice per seed slot. `prim_l` sits in position 4
    // between `prim_s` and `key_bits`, matching the C ABI's
    // positional layout. Empty `prim_l` disables the dedicated
    // lockSeed slot.
    static Encryptor Mixed(std::string_view prim_n,
                           std::string_view prim_d,
                           std::string_view prim_s,
                           std::string_view prim_l,
                           int key_bits,
                           std::string_view mac) {
        itb_encryptor_t* h = nullptr;
        detail::NulView prim_n_nv{prim_n};
        detail::NulView prim_d_nv{prim_d};
        detail::NulView prim_s_nv{prim_s};
        detail::NulView prim_l_nv{prim_l};
        detail::NulView mac_nv{mac};
        int rc = itb_encryptor_new_mixed(
            prim_n_nv.c_str(),
            prim_d_nv.c_str(),
            prim_s_nv.c_str(),
            prim_l_nv.c_str(),
            key_bits,
            mac_nv.c_str(),
            &h);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return Encryptor{h};
    }

    // Mixed-primitive Triple-Ouroboros constructor — `prim_l` sits
    // between `prim_s3` and `key_bits`, matching the C ABI's
    // positional layout.
    static Encryptor Mixed3(std::string_view prim_n,
                            std::string_view prim_d1,
                            std::string_view prim_d2,
                            std::string_view prim_d3,
                            std::string_view prim_s1,
                            std::string_view prim_s2,
                            std::string_view prim_s3,
                            std::string_view prim_l,
                            int key_bits,
                            std::string_view mac) {
        itb_encryptor_t* h = nullptr;
        detail::NulView prim_n_nv{prim_n};
        detail::NulView prim_d1_nv{prim_d1};
        detail::NulView prim_d2_nv{prim_d2};
        detail::NulView prim_d3_nv{prim_d3};
        detail::NulView prim_s1_nv{prim_s1};
        detail::NulView prim_s2_nv{prim_s2};
        detail::NulView prim_s3_nv{prim_s3};
        detail::NulView prim_l_nv{prim_l};
        detail::NulView mac_nv{mac};
        int rc = itb_encryptor_new_mixed3(
            prim_n_nv.c_str(),
            prim_d1_nv.c_str(),
            prim_d2_nv.c_str(),
            prim_d3_nv.c_str(),
            prim_s1_nv.c_str(),
            prim_s2_nv.c_str(),
            prim_s3_nv.c_str(),
            prim_l_nv.c_str(),
            key_bits,
            mac_nv.c_str(),
            &h);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return Encryptor{h};
    }

    Encryptor(const Encryptor&) = delete;
    Encryptor& operator=(const Encryptor&) = delete;

    Encryptor(Encryptor&& other) noexcept
        : handle_{other.handle_}, closed_{other.closed_} {
        other.handle_ = nullptr;
        other.closed_ = true;
    }

    Encryptor& operator=(Encryptor&& other) noexcept {
        if (this != &other) {
            release();
            handle_ = other.handle_;
            closed_ = other.closed_;
            other.handle_ = nullptr;
            other.closed_ = true;
        }
        return *this;
    }

    ~Encryptor() noexcept { release(); }

    // ---- Lifecycle ----------------------------------------------

    // Zeroes the encryptor's PRF / MAC / seed material on the Go
    // side and wipes the C-binding's internal output cache.
    // Idempotent — repeated `close()` calls return without error.
    // Subsequent calls on the closed encryptor (cipher, setters,
    // getters, persist) raise `ItbError(STATUS_EASY_CLOSED)`.
    void close() {
        if (closed_ || handle_ == nullptr) {
            closed_ = true;
            return;
        }
        int rc = itb_encryptor_close(handle_);
        closed_ = true;
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
    }

    bool is_closed() const noexcept { return closed_ || handle_ == nullptr; }

    // ---- Cipher entry points -----------------------------------

    std::vector<std::uint8_t> encrypt(const std::uint8_t* data,
                                      std::size_t len) {
        check_open();
        std::uint8_t* out_buf = nullptr;
        std::size_t out_len = 0;
        int rc = itb_encryptor_encrypt(handle_, data, len,
                                       &out_buf, &out_len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return detail::consume_buffer(out_buf, out_len);
    }

    std::vector<std::uint8_t> decrypt(const std::uint8_t* data,
                                      std::size_t len) {
        check_open();
        std::uint8_t* out_buf = nullptr;
        std::size_t out_len = 0;
        int rc = itb_encryptor_decrypt(handle_, data, len,
                                       &out_buf, &out_len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return detail::consume_buffer(out_buf, out_len);
    }

    std::vector<std::uint8_t> encrypt_auth(const std::uint8_t* data,
                                           std::size_t len) {
        check_open();
        std::uint8_t* out_buf = nullptr;
        std::size_t out_len = 0;
        int rc = itb_encryptor_encrypt_auth(handle_, data, len,
                                            &out_buf, &out_len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return detail::consume_buffer(out_buf, out_len);
    }

    std::vector<std::uint8_t> decrypt_auth(const std::uint8_t* data,
                                           std::size_t len) {
        check_open();
        std::uint8_t* out_buf = nullptr;
        std::size_t out_len = 0;
        int rc = itb_encryptor_decrypt_auth(handle_, data, len,
                                            &out_buf, &out_len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return detail::consume_buffer(out_buf, out_len);
    }

    // Convenience overloads for `std::vector<uint8_t>` and
    // `std::string_view`. Each forwards to the primary `(data, len)`
    // overload above; no per-overload code duplication.
    std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& v) {
        return encrypt(v.data(), v.size());
    }
    std::vector<std::uint8_t> encrypt(std::string_view s) {
        return encrypt(reinterpret_cast<const std::uint8_t*>(s.data()),
                       s.size());
    }

    std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& v) {
        return decrypt(v.data(), v.size());
    }
    std::vector<std::uint8_t> decrypt(std::string_view s) {
        return decrypt(reinterpret_cast<const std::uint8_t*>(s.data()),
                       s.size());
    }

    std::vector<std::uint8_t> encrypt_auth(const std::vector<std::uint8_t>& v) {
        return encrypt_auth(v.data(), v.size());
    }
    std::vector<std::uint8_t> encrypt_auth(std::string_view s) {
        return encrypt_auth(reinterpret_cast<const std::uint8_t*>(s.data()),
                            s.size());
    }

    std::vector<std::uint8_t> decrypt_auth(const std::vector<std::uint8_t>& v) {
        return decrypt_auth(v.data(), v.size());
    }
    std::vector<std::uint8_t> decrypt_auth(std::string_view s) {
        return decrypt_auth(reinterpret_cast<const std::uint8_t*>(s.data()),
                            s.size());
    }

    // ---- Streaming AEAD member surface --------------------------
    //
    // Method-style entry points for the encryptor-bound Streaming AEAD
    // pair. Forwards to the free functions
    // `itb::encryptor_stream_encrypt_auth` /
    // `itb::encryptor_stream_decrypt_auth` declared in
    // `<itb/streams.hpp>`. Object-style consumers reach the streaming
    // path without naming the free function explicitly.
    //
    // Definitions live at the bottom of `<itb/streams.hpp>` so the
    // body has access to the helper context types defined alongside
    // the free functions. Including only `<itb/encryptor.hpp>` is not
    // sufficient to call these — pull in `<itb.hpp>` or
    // `<itb/streams.hpp>`.
    void stream_encrypt_auth(
        std::function<std::size_t(std::uint8_t*, std::size_t)> read,
        std::function<void(const std::uint8_t*, std::size_t)> write,
        std::size_t chunk_size = static_cast<std::size_t>(16 * 1024 * 1024));

    void stream_decrypt_auth(
        std::function<std::size_t(std::uint8_t*, std::size_t)> read,
        std::function<void(const std::uint8_t*, std::size_t)> write,
        std::size_t chunk_size = static_cast<std::size_t>(16 * 1024 * 1024));

    // ---- Per-instance configuration setters --------------------

    void set_nonce_bits(int n) {
        check_open();
        detail::check(itb_encryptor_set_nonce_bits(handle_, n));
    }
    void set_barrier_fill(int n) {
        check_open();
        detail::check(itb_encryptor_set_barrier_fill(handle_, n));
    }
    void set_bit_soup(int mode) {
        check_open();
        detail::check(itb_encryptor_set_bit_soup(handle_, mode));
    }
    void set_lock_soup(int mode) {
        check_open();
        detail::check(itb_encryptor_set_lock_soup(handle_, mode));
    }
    void set_lock_seed(int mode) {
        check_open();
        detail::check(itb_encryptor_set_lock_seed(handle_, mode));
    }
    void set_chunk_size(int n) {
        check_open();
        detail::check(itb_encryptor_set_chunk_size(handle_, n));
    }

    // ---- Read-only field accessors ------------------------------

    std::string primitive() const {
        check_open();
        itb_encryptor_t* h = handle_;
        return detail::read_two_call_string(
            [h](char* buf, std::size_t cap, std::size_t* out_len) {
                return itb_encryptor_primitive(h, buf, cap, out_len);
            });
    }

    std::string primitive_at(int slot) const {
        check_open();
        itb_encryptor_t* h = handle_;
        return detail::read_two_call_string(
            [h, slot](char* buf, std::size_t cap, std::size_t* out_len) {
                return itb_encryptor_primitive_at(h, slot, buf, cap, out_len);
            });
    }

    std::string mac_name() const {
        check_open();
        itb_encryptor_t* h = handle_;
        return detail::read_two_call_string(
            [h](char* buf, std::size_t cap, std::size_t* out_len) {
                return itb_encryptor_mac_name(h, buf, cap, out_len);
            });
    }

    int key_bits() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_key_bits(handle_, &v));
        return v;
    }
    int mode() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_mode(handle_, &v));
        return v;
    }
    int seed_count() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_seed_count(handle_, &v));
        return v;
    }
    int nonce_bits() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_nonce_bits(handle_, &v));
        return v;
    }
    int header_size() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_header_size(handle_, &v));
        return v;
    }
    bool has_prf_keys() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_has_prf_keys(handle_, &v));
        return v != 0;
    }
    bool is_mixed() const {
        check_open();
        int v = 0;
        detail::check(itb_encryptor_is_mixed(handle_, &v));
        return v != 0;
    }

    std::size_t parse_chunk_len(const std::uint8_t* header,
                                std::size_t header_len) const {
        check_open();
        std::size_t out = 0;
        detail::check(itb_encryptor_parse_chunk_len(
            handle_, header, header_len, &out));
        return out;
    }

    std::size_t parse_chunk_len(const std::vector<std::uint8_t>& header) const {
        return parse_chunk_len(header.data(), header.size());
    }

    // ---- Material getters (defensive copies) -------------------

    std::vector<std::uint64_t> seed_components(int slot) const {
        check_open();
        std::size_t cap = 0;
        int rc = itb_encryptor_seed_components(handle_, slot,
                                               nullptr, 0, &cap);
        if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
            detail::throw_from_status(rc);
        }
        if (cap == 0) {
            return {};
        }
        std::vector<std::uint64_t> out(cap);
        std::size_t got = 0;
        detail::check(itb_encryptor_seed_components(
            handle_, slot, out.data(), cap, &got));
        out.resize(got);
        return out;
    }

    std::vector<std::uint8_t> prf_key(int slot) const {
        check_open();
        std::size_t cap = 0;
        int rc = itb_encryptor_prf_key(handle_, slot, nullptr, 0, &cap);
        if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
            detail::throw_from_status(rc);
        }
        if (cap == 0) {
            return {};
        }
        std::vector<std::uint8_t> out(cap);
        std::size_t got = 0;
        detail::check(itb_encryptor_prf_key(
            handle_, slot, out.data(), cap, &got));
        out.resize(got);
        return out;
    }

    std::vector<std::uint8_t> mac_key() const {
        check_open();
        std::size_t cap = 0;
        int rc = itb_encryptor_mac_key(handle_, nullptr, 0, &cap);
        if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
            detail::throw_from_status(rc);
        }
        if (cap == 0) {
            return {};
        }
        std::vector<std::uint8_t> out(cap);
        std::size_t got = 0;
        detail::check(itb_encryptor_mac_key(
            handle_, out.data(), cap, &got));
        out.resize(got);
        return out;
    }

    // ---- Persistence (export / import) -------------------------

    std::vector<std::uint8_t> export_state() const {
        check_open();
        std::uint8_t* buf = nullptr;
        std::size_t len = 0;
        int rc = itb_encryptor_export(handle_, &buf, &len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return detail::consume_buffer(buf, len);
    }

    void import_state(const std::uint8_t* blob, std::size_t len) {
        check_open();
        int rc = itb_encryptor_import(handle_, blob, len);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
    }

    void import_state(const std::vector<std::uint8_t>& blob) {
        import_state(blob.data(), blob.size());
    }

    // ---- Raw handle access (advanced use) -----------------------

    // Returns the underlying C binding handle. Exposed for
    // callers that need to mix the C++ wrapper with raw `itb_*`
    // calls. The handle's lifetime remains owned by this `Encryptor`
    // — do NOT call `itb_encryptor_close` / `itb_encryptor_free`
    // on the returned pointer.
    itb_encryptor_t* raw_handle() const noexcept { return handle_; }

private:
    explicit Encryptor(itb_encryptor_t* taken) noexcept : handle_{taken} {}

    void check_open() const {
        if (closed_ || handle_ == nullptr) {
            throw ItbError{status::kEasyClosed,
                           "encryptor has been closed"};
        }
    }

    void release() noexcept {
        if (handle_ != nullptr) {
            // Skip the close call when the user has already invoked
            // close() explicitly — guards against a future C-binding
            // regression that loses the idempotent-close contract,
            // and makes the destructor robust against any non-zero
            // post-close return code on the C side.
            if (!closed_) {
                (void)itb_encryptor_close(handle_);
            }
            itb_encryptor_free(handle_);
            handle_ = nullptr;
        }
        closed_ = true;
    }

    itb_encryptor_t* handle_ = nullptr;
    bool closed_ = false;
};

} // namespace itb
