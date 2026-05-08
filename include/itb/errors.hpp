// errors.hpp — exception hierarchy + status code surface.
//
// The C binding's `itb_status_t` enum is mirrored as inline constexpr
// constants in the `itb::status` namespace, and every fallible
// `itb_*` call's status code translates into one of five exception
// classes:
//
//   itb::ItbError                   — base class; carries `int code()`
//                                     plus a `std::string message`.
//   itb::ItbEasyMismatchError       — STATUS_EASY_MISMATCH; adds a
//                                     `.field()` JSON-field accessor.
//   itb::ItbBlobModeMismatchError   — STATUS_BLOB_MODE_MISMATCH.
//   itb::ItbBlobMalformedError      — STATUS_BLOB_MALFORMED.
//   itb::ItbBlobVersionTooNewError  — STATUS_BLOB_VERSION_TOO_NEW.
//
// The four subclasses inherit from `ItbError` so callers can catch
// the base class generically. Free functions `itb::last_error()` and
// `itb::last_mismatch_field()` expose the per-thread libitb
// diagnostic surface independently of the exception path, for
// callers that need the diagnostic outside of a try / catch block.

#pragma once

#include <itb.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace itb {

// ---- status codes (mirror itb_status_t bit-identically) ----------

namespace status {

inline constexpr int kOk                          = ITB_OK;
inline constexpr int kBadHash                     = ITB_BAD_HASH;
inline constexpr int kBadKeyBits                  = ITB_BAD_KEY_BITS;
inline constexpr int kBadHandle                   = ITB_BAD_HANDLE;
inline constexpr int kBadInput                    = ITB_BAD_INPUT;
inline constexpr int kBufferTooSmall              = ITB_BUFFER_TOO_SMALL;
inline constexpr int kEncryptFailed               = ITB_ENCRYPT_FAILED;
inline constexpr int kDecryptFailed               = ITB_DECRYPT_FAILED;
inline constexpr int kSeedWidthMix                = ITB_SEED_WIDTH_MIX;
inline constexpr int kBadMac                      = ITB_BAD_MAC;
inline constexpr int kMacFailure                  = ITB_MAC_FAILURE;

inline constexpr int kEasyClosed                  = ITB_EASY_CLOSED;
inline constexpr int kEasyMalformed               = ITB_EASY_MALFORMED;
inline constexpr int kEasyVersionTooNew           = ITB_EASY_VERSION_TOO_NEW;
inline constexpr int kEasyUnknownPrimitive        = ITB_EASY_UNKNOWN_PRIMITIVE;
inline constexpr int kEasyUnknownMac              = ITB_EASY_UNKNOWN_MAC;
inline constexpr int kEasyBadKeyBits              = ITB_EASY_BAD_KEY_BITS;
inline constexpr int kEasyMismatch                = ITB_EASY_MISMATCH;
inline constexpr int kEasyLockSeedAfterEncrypt    = ITB_EASY_LOCKSEED_AFTER_ENCRYPT;

inline constexpr int kBlobModeMismatch            = ITB_BLOB_MODE_MISMATCH;
inline constexpr int kBlobMalformed               = ITB_BLOB_MALFORMED;
inline constexpr int kBlobVersionTooNew           = ITB_BLOB_VERSION_TOO_NEW;
inline constexpr int kBlobTooManyOpts             = ITB_BLOB_TOO_MANY_OPTS;

inline constexpr int kStreamTruncated             = ITB_STREAM_TRUNCATED;
inline constexpr int kStreamAfterFinal            = ITB_STREAM_AFTER_FINAL;

inline constexpr int kInternal                    = ITB_INTERNAL;

// Returns a stable string name for a status code, or `"unknown"` for
// anything outside the defined set. Useful in log messages and the
// `ItbError::what()` payload.
inline std::string_view name(int code) noexcept {
    switch (code) {
    case kOk:                          return "OK";
    case kBadHash:                     return "BAD_HASH";
    case kBadKeyBits:                  return "BAD_KEY_BITS";
    case kBadHandle:                   return "BAD_HANDLE";
    case kBadInput:                    return "BAD_INPUT";
    case kBufferTooSmall:              return "BUFFER_TOO_SMALL";
    case kEncryptFailed:               return "ENCRYPT_FAILED";
    case kDecryptFailed:               return "DECRYPT_FAILED";
    case kSeedWidthMix:                return "SEED_WIDTH_MIX";
    case kBadMac:                      return "BAD_MAC";
    case kMacFailure:                  return "MAC_FAILURE";
    case kEasyClosed:                  return "EASY_CLOSED";
    case kEasyMalformed:               return "EASY_MALFORMED";
    case kEasyVersionTooNew:           return "EASY_VERSION_TOO_NEW";
    case kEasyUnknownPrimitive:        return "EASY_UNKNOWN_PRIMITIVE";
    case kEasyUnknownMac:              return "EASY_UNKNOWN_MAC";
    case kEasyBadKeyBits:              return "EASY_BAD_KEY_BITS";
    case kEasyMismatch:                return "EASY_MISMATCH";
    case kEasyLockSeedAfterEncrypt:    return "EASY_LOCKSEED_AFTER_ENCRYPT";
    case kBlobModeMismatch:            return "BLOB_MODE_MISMATCH";
    case kBlobMalformed:               return "BLOB_MALFORMED";
    case kBlobVersionTooNew:           return "BLOB_VERSION_TOO_NEW";
    case kBlobTooManyOpts:             return "BLOB_TOO_MANY_OPTS";
    case kStreamTruncated:             return "STREAM_TRUNCATED";
    case kStreamAfterFinal:            return "STREAM_AFTER_FINAL";
    case kInternal:                    return "INTERNAL";
    default:                           return "unknown";
    }
}

} // namespace status

// ---- diagnostic accessors ----------------------------------------

// Returns the textual diagnostic associated with the most recent
// non-OK libitb call on the calling thread, or the empty string when
// the thread has not yet seen a failing call. The C binding's
// `itb_last_error()` writes into thread-local storage owned by the
// binding; this wrapper copies the bytes out so the returned string
// is safe to retain across subsequent libitb calls.
inline std::string last_error() {
    const char* p = itb_last_error();
    if (p == nullptr) {
        return std::string{};
    }
    return std::string{p};
}

// Returns the offending JSON field name from the most recent
// `Encryptor::import_state` call that surfaced
// `STATUS_EASY_MISMATCH` on the calling thread. Returns
// `std::nullopt` when the most recent failure on this thread was
// not a mismatch (or no failure has occurred yet).
//
// `Encryptor::import_state` already attaches this name to the
// raised `ItbEasyMismatchError`'s `.field()` accessor; this free
// function is exposed for callers that need to read the field
// independently of the exception path.
//
// (Implementation defined below the exception classes — the body
// throws `ItbError` to surface a future C-binding contract violation
// as a loud `STATUS_INTERNAL` rather than masking it as `nullopt`.)
inline std::optional<std::string> last_mismatch_field();

// ---- exception hierarchy -----------------------------------------

// Base class for every libitb-originating failure. Carries the
// structural status code (numeric) plus the textual diagnostic
// captured at construction time. The status code is the only piece
// of `ItbError` that is reliably attributable to the failing call —
// the textual message is read from a process-wide TLS slot inside
// libitb at the moment of construction, so a sibling thread that
// makes a libitb call between the failing call and the
// `ItbError` construction can overwrite the message.
class ItbError : public std::exception {
public:
    ItbError(int code, std::string message)
        : code_{code}, message_{std::move(message)} {
        formatted_ = format_message(code_, message_);
    }

    explicit ItbError(int code) : ItbError(code, last_error()) {}

    int code() const noexcept { return code_; }

    std::string_view message() const noexcept { return message_; }

    std::string_view name() const noexcept { return status::name(code_); }

    const char* what() const noexcept override { return formatted_.c_str(); }

private:
    static std::string format_message(int code, const std::string& message) {
        std::string out = "itb: ";
        out.append(status::name(code));
        out.append(" (");
        out.append(std::to_string(code));
        out.append(")");
        if (!message.empty()) {
            out.append(": ");
            out.append(message);
        }
        return out;
    }

    int code_;
    std::string message_;
    std::string formatted_;
};

// `STATUS_EASY_MISMATCH` — raised on import / peek when the saved
// blob's primitive / key_bits / mode / mac does not match the
// receiving encryptor's configuration. Carries the offending JSON
// field name for callers that need to surface a precise diagnostic.
class ItbEasyMismatchError : public ItbError {
public:
    ItbEasyMismatchError(std::string field, std::string message)
        : ItbError{status::kEasyMismatch, std::move(message)},
          field_{std::move(field)} {}

    explicit ItbEasyMismatchError(std::string field)
        : ItbError{status::kEasyMismatch}, field_{std::move(field)} {}

    std::string_view field() const noexcept { return field_; }

private:
    std::string field_;
};

// `STATUS_BLOB_MODE_MISMATCH` — the parsed blob carries a Single
// payload but the importer wants Triple, or vice versa.
class ItbBlobModeMismatchError : public ItbError {
public:
    using ItbError::ItbError;
    ItbBlobModeMismatchError() : ItbError{status::kBlobModeMismatch} {}
};

// `STATUS_BLOB_MALFORMED` — JSON parse failure, shape failure, or
// a blob produced under a too-new version (peek_config conflates
// version-too-new with malformed; only `import` differentiates).
class ItbBlobMalformedError : public ItbError {
public:
    using ItbError::ItbError;
    ItbBlobMalformedError() : ItbError{status::kBlobMalformed} {}
};

// `STATUS_BLOB_VERSION_TOO_NEW` — blob's version field is higher
// than the consumer's libitb supports. Surfaced by
// `import_state` only; `peek_config` returns `BlobMalformed` for
// the same condition.
class ItbBlobVersionTooNewError : public ItbError {
public:
    using ItbError::ItbError;
    ItbBlobVersionTooNewError() : ItbError{status::kBlobVersionTooNew} {}
};

// `STATUS_STREAM_TRUNCATED` — Streaming AEAD decoder reached
// end-of-input without observing the terminating chunk
// (`final_flag = 1`). Indicates the wire transcript was cut short;
// the decoder is fail-stop and emits no plaintext.
class ItbStreamTruncatedError : public ItbError {
public:
    using ItbError::ItbError;
    ItbStreamTruncatedError() : ItbError{status::kStreamTruncated} {}
};

// `STATUS_STREAM_AFTER_FINAL` — Streaming AEAD decoder observed
// extra chunk bytes following the terminating chunk. Indicates an
// adversary appended forged chunks past the legitimate end of the
// transcript.
class ItbStreamAfterFinalError : public ItbError {
public:
    using ItbError::ItbError;
    ItbStreamAfterFinalError() : ItbError{status::kStreamAfterFinal} {}
};

// ---- last_mismatch_field implementation --------------------------
//
// Defined here, after `ItbError`, so the contract-violation paths
// can throw `ItbError{status::kInternal, ...}` directly.
inline std::optional<std::string> last_mismatch_field() {
    std::size_t visible = 0;
    int rc = itb_easy_last_mismatch_field(nullptr, 0, &visible);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        return std::nullopt;
    }
    if (visible == 0) {
        return std::nullopt;
    }
    // The probe reports the visible (NUL-stripped) length; the read
    // call writes `visible + 1` bytes total (NUL terminator included)
    // and needs `cap >= visible + 1`.
    std::string buf(visible + 1, '\0');
    rc = itb_easy_last_mismatch_field(buf.data(), buf.size(), &visible);
    if (rc != ITB_OK) {
        // Surface a future C-binding regression as `STATUS_INTERNAL`
        // rather than masking it as a `nullopt` return — the second
        // call cannot legitimately fail with the buffer sized to
        // `probe_visible + 1`. Same defensive policy applied at the
        // peek_config / read_two_call_string probe sites.
        throw ItbError{status::kInternal,
                       "last_mismatch_field two-call probe contract "
                       "violation: second-call read returned non-OK"};
    }
    if (visible == 0) {
        return std::nullopt;
    }
    if (visible + 1 > buf.size()) {
        throw ItbError{status::kInternal,
                       "last_mismatch_field two-call probe contract "
                       "violation: post-call visible exceeds capacity"};
    }
    buf.resize(visible);
    return buf;
}

// ---- internal dispatch helper ------------------------------------

namespace detail {

// Translates a non-OK status code into the appropriate exception
// class and throws. The diagnostic message is read from libitb's
// thread-local last-error slot at construction time; on
// `STATUS_EASY_MISMATCH` the offending JSON field name is also
// pulled from libitb and attached to the raised exception's
// `.field()` accessor.
//
// Caller contract: invoke only when `rc != ITB_OK`. The function
// never returns; callers should mark it `[[noreturn]]` at the call
// site if required by control-flow analysis.
[[noreturn]] inline void throw_from_status(int rc) {
    std::string message = last_error();
    switch (rc) {
    case status::kEasyMismatch: {
        std::string field;
        auto f = last_mismatch_field();
        if (f.has_value()) {
            field = std::move(*f);
        }
        throw ItbEasyMismatchError{std::move(field), std::move(message)};
    }
    case status::kBlobModeMismatch:
        throw ItbBlobModeMismatchError{rc, std::move(message)};
    case status::kBlobMalformed:
        throw ItbBlobMalformedError{rc, std::move(message)};
    case status::kBlobVersionTooNew:
        throw ItbBlobVersionTooNewError{rc, std::move(message)};
    case status::kStreamTruncated:
        throw ItbStreamTruncatedError{rc, std::move(message)};
    case status::kStreamAfterFinal:
        throw ItbStreamAfterFinalError{rc, std::move(message)};
    default:
        throw ItbError{rc, std::move(message)};
    }
}

// Convenience helper: throws on non-OK rc, returns silently on OK.
// Inline so every translation unit can call it without an extra
// link-time symbol.
inline void check(int rc) {
    if (rc != ITB_OK) {
        throw_from_status(rc);
    }
}

} // namespace detail

} // namespace itb
