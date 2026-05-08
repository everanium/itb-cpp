// cipher.hpp — low-level free-function cipher entry points.
//
// Thin wrappers over the underlying single- and triple-Ouroboros
// cipher entry points. Each call allocates an output buffer at the
// C-binding boundary; the wrapper copies the bytes into a freshly-
// allocated `std::vector<std::uint8_t>`, frees the C-side buffer
// via `itb_buffer_free`, and returns the vector to the caller.
//
// Empty plaintext / ciphertext propagates as
// `ItbError(STATUS_ENCRYPT_FAILED)` / `ItbError(STATUS_DECRYPT_FAILED)`
// — libitb itself rejects empty inputs ("itb: empty data") and the
// binding surfaces the rejection verbatim without short-circuiting.
//
// Threading. The free-function cipher entry points are thread-safe
// under concurrent invocation provided each call's `Seed` (and `Mac`)
// arguments are distinct from every other in-flight call's. Each
// call allocates its own output buffer, takes the seeds by const
// reference, and dispatches into the libitb worker pool independently.
// Two concurrent calls that share the SAME `Seed` instance race on
// the C-binding's per-Seed PRF state and corrupt both running
// operations; pass distinct `Seed` instances per thread, or
// serialise externally.

#pragma once

#include <itb.h>
#include <itb/encryptor.hpp>  // for detail::consume_buffer
#include <itb/errors.hpp>
#include <itb/mac.hpp>
#include <itb/seed.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace itb {

// ---- Single Ouroboros (3 seeds) ----------------------------------

inline std::vector<std::uint8_t> encrypt(const Seed& noise,
                                         const Seed& data,
                                         const Seed& start,
                                         const std::uint8_t* plaintext,
                                         std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_encrypt(noise.raw_handle(), data.raw_handle(),
                         start.raw_handle(),
                         plaintext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> decrypt(const Seed& noise,
                                         const Seed& data,
                                         const Seed& start,
                                         const std::uint8_t* ciphertext,
                                         std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_decrypt(noise.raw_handle(), data.raw_handle(),
                         start.raw_handle(),
                         ciphertext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> encrypt_auth(const Seed& noise,
                                              const Seed& data,
                                              const Seed& start,
                                              const Mac& mac,
                                              const std::uint8_t* plaintext,
                                              std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_encrypt_auth(noise.raw_handle(), data.raw_handle(),
                              start.raw_handle(), mac.raw_handle(),
                              plaintext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> decrypt_auth(const Seed& noise,
                                              const Seed& data,
                                              const Seed& start,
                                              const Mac& mac,
                                              const std::uint8_t* ciphertext,
                                              std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_decrypt_auth(noise.raw_handle(), data.raw_handle(),
                              start.raw_handle(), mac.raw_handle(),
                              ciphertext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

// ---- convenience overloads (Single) ------------------------------

inline std::vector<std::uint8_t> encrypt(const Seed& n, const Seed& d,
                                         const Seed& s,
                                         const std::vector<std::uint8_t>& v) {
    return encrypt(n, d, s, v.data(), v.size());
}
inline std::vector<std::uint8_t> encrypt(const Seed& n, const Seed& d,
                                         const Seed& s,
                                         std::string_view sv) {
    return encrypt(n, d, s,
                   reinterpret_cast<const std::uint8_t*>(sv.data()),
                   sv.size());
}

inline std::vector<std::uint8_t> decrypt(const Seed& n, const Seed& d,
                                         const Seed& s,
                                         const std::vector<std::uint8_t>& v) {
    return decrypt(n, d, s, v.data(), v.size());
}

inline std::vector<std::uint8_t> encrypt_auth(const Seed& n, const Seed& d,
                                              const Seed& s, const Mac& m,
                                              const std::vector<std::uint8_t>& v) {
    return encrypt_auth(n, d, s, m, v.data(), v.size());
}
inline std::vector<std::uint8_t> encrypt_auth(const Seed& n, const Seed& d,
                                              const Seed& s, const Mac& m,
                                              std::string_view sv) {
    return encrypt_auth(n, d, s, m,
                        reinterpret_cast<const std::uint8_t*>(sv.data()),
                        sv.size());
}

inline std::vector<std::uint8_t> decrypt_auth(const Seed& n, const Seed& d,
                                              const Seed& s, const Mac& m,
                                              const std::vector<std::uint8_t>& v) {
    return decrypt_auth(n, d, s, m, v.data(), v.size());
}

// ---- Triple Ouroboros (7 seeds) ----------------------------------

inline std::vector<std::uint8_t> encrypt_triple(const Seed& noise,
                                                const Seed& data1,
                                                const Seed& data2,
                                                const Seed& data3,
                                                const Seed& start1,
                                                const Seed& start2,
                                                const Seed& start3,
                                                const std::uint8_t* plaintext,
                                                std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_encrypt_triple(noise.raw_handle(),
                                data1.raw_handle(), data2.raw_handle(),
                                data3.raw_handle(),
                                start1.raw_handle(), start2.raw_handle(),
                                start3.raw_handle(),
                                plaintext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> decrypt_triple(const Seed& noise,
                                                const Seed& data1,
                                                const Seed& data2,
                                                const Seed& data3,
                                                const Seed& start1,
                                                const Seed& start2,
                                                const Seed& start3,
                                                const std::uint8_t* ciphertext,
                                                std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_decrypt_triple(noise.raw_handle(),
                                data1.raw_handle(), data2.raw_handle(),
                                data3.raw_handle(),
                                start1.raw_handle(), start2.raw_handle(),
                                start3.raw_handle(),
                                ciphertext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> encrypt_auth_triple(const Seed& noise,
                                                     const Seed& data1,
                                                     const Seed& data2,
                                                     const Seed& data3,
                                                     const Seed& start1,
                                                     const Seed& start2,
                                                     const Seed& start3,
                                                     const Mac& mac,
                                                     const std::uint8_t* plaintext,
                                                     std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_encrypt_auth_triple(noise.raw_handle(),
                                     data1.raw_handle(), data2.raw_handle(),
                                     data3.raw_handle(),
                                     start1.raw_handle(), start2.raw_handle(),
                                     start3.raw_handle(),
                                     mac.raw_handle(),
                                     plaintext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

inline std::vector<std::uint8_t> decrypt_auth_triple(const Seed& noise,
                                                     const Seed& data1,
                                                     const Seed& data2,
                                                     const Seed& data3,
                                                     const Seed& start1,
                                                     const Seed& start2,
                                                     const Seed& start3,
                                                     const Mac& mac,
                                                     const std::uint8_t* ciphertext,
                                                     std::size_t len) {
    std::uint8_t* out = nullptr;
    std::size_t out_len = 0;
    int rc = itb_decrypt_auth_triple(noise.raw_handle(),
                                     data1.raw_handle(), data2.raw_handle(),
                                     data3.raw_handle(),
                                     start1.raw_handle(), start2.raw_handle(),
                                     start3.raw_handle(),
                                     mac.raw_handle(),
                                     ciphertext, len, &out, &out_len);
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
    return detail::consume_buffer(out, out_len);
}

// ---- convenience overloads (Triple) ------------------------------

inline std::vector<std::uint8_t> encrypt_triple(const Seed& n,
                                                const Seed& d1, const Seed& d2,
                                                const Seed& d3,
                                                const Seed& s1, const Seed& s2,
                                                const Seed& s3,
                                                const std::vector<std::uint8_t>& v) {
    return encrypt_triple(n, d1, d2, d3, s1, s2, s3, v.data(), v.size());
}

inline std::vector<std::uint8_t> decrypt_triple(const Seed& n,
                                                const Seed& d1, const Seed& d2,
                                                const Seed& d3,
                                                const Seed& s1, const Seed& s2,
                                                const Seed& s3,
                                                const std::vector<std::uint8_t>& v) {
    return decrypt_triple(n, d1, d2, d3, s1, s2, s3, v.data(), v.size());
}

inline std::vector<std::uint8_t> encrypt_auth_triple(const Seed& n,
                                                     const Seed& d1, const Seed& d2,
                                                     const Seed& d3,
                                                     const Seed& s1, const Seed& s2,
                                                     const Seed& s3,
                                                     const Mac& m,
                                                     const std::vector<std::uint8_t>& v) {
    return encrypt_auth_triple(n, d1, d2, d3, s1, s2, s3, m,
                               v.data(), v.size());
}

inline std::vector<std::uint8_t> decrypt_auth_triple(const Seed& n,
                                                     const Seed& d1, const Seed& d2,
                                                     const Seed& d3,
                                                     const Seed& s1, const Seed& s2,
                                                     const Seed& s3,
                                                     const Mac& m,
                                                     const std::vector<std::uint8_t>& v) {
    return decrypt_auth_triple(n, d1, d2, d3, s1, s2, s3, m,
                               v.data(), v.size());
}

} // namespace itb
