/*
 * internal.hpp — shared internals of the ITB C++ binding.
 *
 * Not installed; consumers include only <itb.hpp>. The binding links
 * against libitb.so at compile time, so the generated libitb.h
 * prototypes are the FFI surface — no runtime symbol loading.
 */

#ifndef ITB_INTERNAL_HPP
#define ITB_INTERNAL_HPP

#include "itb.hpp"

namespace itb::detail {

/* Floor capacity for blob output buffers (init / rekey). */
inline constexpr std::size_t kBlobCap = 64 * 1024;

/* Feed / drain slice size used by the pump loops. */
inline constexpr std::size_t kPumpBuf = std::size_t{1} << 20;

/* Normalises a raw libitb return code into Status (unknown codes
 * collapse to Status::Internal). */
Status to_status(int rc) noexcept;

/* Throws Error with "<what>: status <rc> (<label>): <last_error()>". */
[[noreturn]] void fail(int rc, const char *what);

/* Status relay for a raw libitb return code. */
inline void check(int rc, const char *what)
{
    if (rc != 0) {
        fail(rc, what);
    }
}

/* Pre-allocation formula for Message outputs:
 * max(131072, payload * 5/4 + 131072). Overflow-guarded. */
std::size_t out_cap(std::size_t payload) noexcept;

/* const-away casts for the void* / char* (non-const) libitb
 * prototypes — Go only reads through these pointers. */
inline void *ffi_bytes(std::span<const std::byte> s) noexcept
{
    return const_cast<void *>(static_cast<const void *>(s.data()));
}

inline void *ffi_bytes(std::span<std::byte> s) noexcept
{
    return static_cast<void *>(s.data());
}

inline char *ffi_str(const std::string &s) noexcept
{
    return const_cast<char *>(s.c_str());
}

} // namespace itb::detail

#endif /* ITB_INTERNAL_HPP */
