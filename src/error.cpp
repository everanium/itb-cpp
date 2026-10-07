/*
 * Status normalisation, last-error fetch, and the Error-throwing
 * failure path shared by every FFI call site.
 */

#include <array>

#include "internal.hpp"

namespace itb {

std::string last_error()
{
    /* The diagnostic is the only text an error carries, so losing it
     * to a short buffer would leave the caller holding a bare number.
     * The library reports the size it needed, so ask again at that
     * size rather than giving up: 2 KiB covers every sentence seen so
     * far, and the retry covers the ones that have not been. */
    std::array<char, 2048> buf{};
    std::size_t need = 0;
    int rc = ITB_LastError(buf.data(), buf.size(), &need);
    if (rc == 0) {
        return {buf.data()};
    }
    if (rc == static_cast<int>(Status::BufferTooSmall) && need > 1) {
        std::string wide(need, '\0');
        std::size_t wrote = 0;
        if (ITB_LastError(wide.data(), wide.size(), &wrote) == 0) {
            return std::string(wide.c_str());
        }
    }
    return {};
}

namespace detail {

Status to_status(int rc) noexcept
{
    switch (rc) {
    case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
    case 8: case 9: case 10: case 11: case 12: case 13: case 14:
    case 15: case 16: case 17: case 19: case 20: case 21: case 22:
    case 23: case 24: case 25: case 26: case 99:
        return static_cast<Status>(rc);
    default:
        return Status::Internal;
    }
}

void fail(int rc, const char *what)
{
    Status st = to_status(rc);
    std::string msg(what);
    msg += ": status ";
    msg += std::to_string(rc);
    msg += ": ";
    msg += last_error();
    throw Error(st, msg);
}

std::size_t out_cap(std::size_t payload) noexcept
{
    constexpr std::size_t floor_cap = 131072;
    std::size_t cap = payload + payload / 4;
    if (cap < payload || cap + floor_cap < cap) {
        return payload; /* overflow-adjacent sizes: exact payload */
    }
    cap += floor_cap;
    return cap > floor_cap ? cap : floor_cap;
}

} // namespace detail

std::size_t out_bound(std::size_t payload) noexcept
{
    return detail::out_cap(payload);
}

} // namespace itb
