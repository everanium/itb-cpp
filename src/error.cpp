/*
 * error.cpp — status labels, status normalisation, last-error fetch,
 * and the Error-throwing failure path shared by every FFI call site.
 */

#include <array>

#include "internal.hpp"

namespace itb {

const char *status_str(Status status) noexcept
{
    switch (status) {
    case Status::Ok:                return "ok";
    case Status::BadHash:           return "unknown hash name";
    case Status::BadKeyBits:        return "invalid key bits";
    case Status::BadHandle:         return "invalid handle";
    case Status::BadInput:          return "invalid input";
    case Status::BufferTooSmall:    return "output buffer too small";
    case Status::EncryptFailed:     return "encrypt failed";
    case Status::DecryptFailed:     return "decrypt failed";
    case Status::SeedWidthMix:      return "seed width mismatch";
    case Status::BadMac:            return "unknown MAC name or invalid MAC handle";
    case Status::MacFailure:        return "MAC verification failed";
    case Status::Reserved11:
    case Status::Reserved12:
    case Status::Reserved13:
    case Status::Reserved14:
    case Status::Reserved15:
    case Status::Reserved16:
    case Status::Reserved17:        return "reserved status";
    case Status::BlobModeMismatch:  return "blob mode mismatch";
    case Status::BlobMalformed:     return "malformed state blob";
    case Status::BlobVersionTooNew: return "blob version too new";
    case Status::BlobTooManyOpts:   return "too many blob export opts";
    case Status::StreamTruncated:   return "stream truncated before terminator";
    case Status::StreamAfterFinal:  return "stream chunk after terminator";
    case Status::TripleClosed:      return "Triple Pipeline is closed";
    case Status::ProfileExists:     return "profile name already registered";
    case Status::Internal:          return "internal error";
    }
    return "unknown status";
}

std::string last_error()
{
    /* The libitb diagnostics are short sentences; 2 KiB covers every
     * message the Go side emits. */
    std::array<char, 2048> buf{};
    std::size_t need = 0;
    int rc = ITB_LastError(buf.data(), buf.size(), &need);
    if (rc != 0) {
        /* BufferTooSmall (diagnostic > 2 KiB) or a load failure —
         * fall back to the empty string rather than partial bytes. */
        return {};
    }
    return {buf.data()};
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
    msg += " (";
    msg += status_str(st);
    msg += ")";
    std::string diag = last_error();
    if (!diag.empty()) {
        msg += ": ";
        msg += diag;
    }
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
