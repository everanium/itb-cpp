/*
 * itb.hpp — public C++ header for the ITB C++ binding.
 *
 * Thin proxy over the libitb shared library's `ITB_Triple_*` surface
 * (cmd/cshared). The binding links against libitb.so at compile time
 * (`-litb_cpp -litb` with an embedded RPATH) — no runtime symbol
 * loading. Every hash-name / MAC-name / cipher-name / profile-name is
 * an opaque string passed through to Go for validation — the binding
 * carries no ITB construction logic.
 *
 * Quick start:
 *
 *     #include <itb.hpp>
 *
 *     itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");
 *     itb::Pipeline receiver =
 *         itb::Pipeline::open("singlemsg-triple-mac-v1", sender.blob());
 *
 *     std::vector<std::uint8_t> wire =
 *         sender.encrypt_message(itb::as_bytes("hi"));
 *     std::vector<std::uint8_t> plain =
 *         receiver.decrypt_message(itb::as_bytes(wire));
 *
 * Ownership. Every handle is RAII-managed: itb::Pipeline releases the
 * Go-side Pipeline in its destructor (zeroing key material first),
 * itb::EncryptStream / itb::DecryptStream cancel and release their
 * session. All handle types are move-only.
 *
 * Errors. Every fallible entry throws itb::Error on a non-OK libitb
 * status; the exception carries the numeric itb::Status plus the
 * Go-side diagnostic snapshot fetched via last_error() at throw time.
 */

#ifndef ITB_HPP
#define ITB_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "libitb.h"

/* Binding version. Tracks the C++ wrapper; call itb::version() for
 * the underlying libitb library version. */
#define ITB_CPP_VERSION "0.3.1"

namespace itb {

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */
/* Mirror cmd/cshared/internal/capi/errors.go numerically. Codes
 * 11..17 are a reserved sentinel block; 19..22 belong to the native
 * Blob surface (not wrapped here but relayed verbatim if libitb ever
 * returns them). */
enum class Status : int {
    Ok               = 0,
    BadHash          = 1,
    BadKeyBits       = 2,
    BadHandle        = 3,
    BadInput         = 4,
    BufferTooSmall   = 5,
    EncryptFailed    = 6,
    DecryptFailed    = 7,
    SeedWidthMix     = 8,
    BadMac           = 9,
    MacFailure       = 10,
    Reserved11       = 11,
    Reserved12       = 12,
    Reserved13       = 13,
    Reserved14       = 14,
    Reserved15       = 15,
    Reserved16       = 16,
    Reserved17       = 17,
    BlobModeMismatch = 19,
    BlobMalformed    = 20,
    BlobVersionTooNew = 21,
    BlobTooManyOpts  = 22,
    StreamTruncated  = 23,
    StreamAfterFinal = 24,
    TripleClosed     = 25,
    ProfileExists    = 26,
    Internal         = 99,
};

/* Short static label for a status code. Never null; the pointer is a
 * string literal. */
const char *status_str(Status status) noexcept;

/* The Go-side diagnostic recorded by the most recent failing libitb
 * call. Process-global last-write-wins on the Go side — fetch it
 * immediately after the failing call; itb::Error already snapshots it
 * at throw time. Empty string when no diagnostic. */
std::string last_error();

/* Thrown by every fallible entry on a non-OK libitb status. what()
 * carries "<context>: status <n> (<label>): <Go diagnostic>". */
class Error : public std::runtime_error {
public:
    Error(Status status, const std::string &what_arg)
        : std::runtime_error(what_arg), status_(status) {}

    Status status() const noexcept { return status_; }

private:
    Status status_;
};

/* ------------------------------------------------------------------ */
/* Byte-view helpers                                                   */
/* ------------------------------------------------------------------ */
/* All byte inputs cross the API as std::span<const std::byte>; these
 * adaptors build such views over the usual byte carriers. */

inline std::span<const std::byte> as_bytes(std::span<const std::uint8_t> s) noexcept
{
    return std::as_bytes(s);
}

inline std::span<const std::byte> as_bytes(const std::vector<std::uint8_t> &v) noexcept
{
    return std::as_bytes(std::span<const std::uint8_t>(v));
}

inline std::span<const std::byte> as_bytes(std::string_view s) noexcept
{
    return {reinterpret_cast<const std::byte *>(s.data()), s.size()};
}

/* Writable-view adaptor for the *_into entries' dst parameter. */
inline std::span<std::byte> as_writable_bytes(std::vector<std::uint8_t> &v) noexcept
{
    return std::as_writable_bytes(std::span<std::uint8_t>(v));
}

/* Upper bound on the produced-output size for a payload of the given
 * length, on the Single Message, one-shot stream, and whole-buffer
 * pump paths (wire expansion plus envelope overhead). Sizes the
 * caller-owned dst buffer for the *_into entries. */
std::size_t out_bound(std::size_t payload) noexcept;

/* ------------------------------------------------------------------ */
/* Opts builder                                                        */
/* ------------------------------------------------------------------ */
/* Accumulates key=value pairs into the URL-query-encoded opts string
 * consumed by init / open / register_profile. The builder performs no
 * validation — Go rejects unknown keys and bad values with a
 * diagnostic relayed through the thrown itb::Error. A plain value
 * type: it owns only the query string, no Go-side handle. */

class Opts {
public:
    Opts() = default;

    /* Appends one key=value pair (both percent-encoded as needed). */
    Opts &set(std::string_view key, std::string_view value);

    /* The built query string ("" for an empty builder). */
    const std::string &query() const noexcept { return query_; }

private:
    std::string query_;
};

/* ------------------------------------------------------------------ */
/* Stream sessions                                                     */
/* ------------------------------------------------------------------ */

/* One read() step: bytes drained plus the finished flag (true once
 * the session has ended AND the output is fully drained). */
struct StreamRead {
    std::size_t n = 0;
    bool finished = false;
};

/* Common machinery of the incremental sessions. A session is a dumb
 * byte pump: bytes go in through write, produced bytes come out
 * through read. All chunking, MAC, envelope, and wire-format
 * decisions stay inside libitb. Move-only; the destructor cancels
 * (if still running) and releases the Go-side session. A session
 * must not outlive its Pipeline. */
class Stream {
public:
    ~Stream() { close(); }

    Stream(Stream &&other) noexcept : handle_(other.handle_)
    {
        other.handle_ = 0;
    }

    Stream &operator=(Stream &&other) noexcept
    {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            other.handle_ = 0;
        }
        return *this;
    }

    Stream(const Stream &) = delete;
    Stream &operator=(const Stream &) = delete;

    /* Feeds src into the session. Blocks until the cipher chain
     * accepts the bytes; errors are sticky. An empty src is a no-op. */
    void write(std::span<const std::byte> src);

    /* Signals end-of-input. Idempotent; a write after end throws
     * Status::BadInput. */
    void end();

    /* Drains up to dst.size() produced bytes into dst. Partial drains
     * are the normal mode (n == 0 when nothing is currently
     * available). After end, an empty-spool read blocks until the
     * terminal bytes arrive or the session errors. */
    StreamRead read(std::span<std::byte> dst);

    /* Cancels (if still running) and releases the session. Safe from
     * any state; idempotent. The destructor calls it silently. */
    void close() noexcept;

protected:
    explicit Stream(std::uintptr_t handle) noexcept : handle_(handle) {}

    std::uintptr_t handle_ = 0;
};

class Pipeline;

/* Plaintext in, wire out. Obtained via Pipeline::encrypt_stream_begin. */
class EncryptStream final : public Stream {
public:
    EncryptStream(EncryptStream &&) = default;
    EncryptStream &operator=(EncryptStream &&) = default;

private:
    friend class Pipeline;
    explicit EncryptStream(std::uintptr_t handle) noexcept : Stream(handle) {}
};

/* Wire in, plaintext out. Obtained via Pipeline::decrypt_stream_begin. */
class DecryptStream final : public Stream {
public:
    DecryptStream(DecryptStream &&) = default;
    DecryptStream &operator=(DecryptStream &&) = default;

private:
    friend class Pipeline;
    explicit DecryptStream(std::uintptr_t handle) noexcept : Stream(handle) {}
};

/* ------------------------------------------------------------------ */
/* Pipeline                                                            */
/* ------------------------------------------------------------------ */

/* One Triple Pipeline session. Move-only; the destructor closes
 * (zeroing key material Go-side) and releases the handle. */
class Pipeline {
public:
    /* Constructs a fresh Pipeline against the named profile. */
    static Pipeline init(std::string_view profile, const Opts &opts = {});

    /* Reconstructs a Pipeline from a blob produced by a sender's
     * init / rekey. Pass empty masters to use the blob-embedded ones;
     * to override, both masters must be supplied non-empty (a
     * half-supplied pair is rejected). */
    static Pipeline open(std::string_view profile,
                         std::span<const std::byte> blob,
                         const Opts &opts = {},
                         std::span<const std::byte> perm_master = {},
                         std::span<const std::byte> wrap_master = {});

    ~Pipeline();

    Pipeline(Pipeline &&other) noexcept;
    Pipeline &operator=(Pipeline &&other) noexcept;
    Pipeline(const Pipeline &) = delete;
    Pipeline &operator=(const Pipeline &) = delete;

    /* The exported session-bundle blob for the receiver side. The
     * view stays valid until the next rekey, move, or destruction. */
    std::span<const std::byte> blob() const noexcept
    {
        return as_bytes(blob_);
    }

    /* Rotates the parallax + wrapper masters and refreshes the blob.
     * Must not run concurrently with cipher calls or open stream
     * sessions on the same Pipeline. */
    void rekey(std::span<const std::byte> perm_master,
               std::span<const std::byte> wrap_master);

    /* Single Message encrypt: one call, one self-contained wire. */
    std::vector<std::uint8_t> encrypt_message(std::span<const std::byte> plain) const;

    /* Receive-side counterpart of encrypt_message. */
    std::vector<std::uint8_t> decrypt_message(std::span<const std::byte> wire) const;

    /* Reusable-buffer Single Message encrypt: writes the wire into
     * the caller-owned dst and returns the byte count written. The
     * FFI write ceiling is dst.size() itself — size dst via
     * itb::out_bound(plain.size()) and reuse it across calls. An
     * undersized dst throws Error with Status::BufferTooSmall (no
     * retry — the caller owns sizing). plain and dst must not
     * overlap; bytes beyond the returned count are undefined. */
    std::size_t encrypt_message_into(std::span<const std::byte> plain,
                                     std::span<std::byte> dst) const;

    /* Receive-side counterpart of encrypt_message_into (same buffer
     * contract). After a failed call — MAC failure included — the
     * contents of dst are unspecified and must not be interpreted. */
    std::size_t decrypt_message_into(std::span<const std::byte> wire,
                                     std::span<std::byte> dst) const;

    /* Pumps the whole plaintext through an incremental encrypt
     * session (begin → write slices → end → drain → free) and returns
     * the concatenated wire. Bounded feed / drain slices internally. */
    std::vector<std::uint8_t> encrypt_stream_pump(std::span<const std::byte> plain) const;

    /* Receive-side counterpart of encrypt_stream_pump. */
    std::vector<std::uint8_t> decrypt_stream_pump(std::span<const std::byte> wire) const;

    /* Reusable-buffer whole-plaintext pump: runs a full incremental
     * encrypt session, draining every produced byte straight into the
     * caller-owned dst (no intermediate copies), and returns the byte
     * count written. Size dst via itb::out_bound(plain.size()) and
     * reuse it across calls. A dst too small for the produced output
     * throws std::invalid_argument. plain and dst must not overlap;
     * bytes beyond the returned count are undefined; after a failed
     * call the contents of dst are unspecified. */
    std::size_t encrypt_stream_pump_into(std::span<const std::byte> plain,
                                         std::span<std::byte> dst) const;

    /* Receive-side counterpart of encrypt_stream_pump_into (same
     * buffer contract). */
    std::size_t decrypt_stream_pump_into(std::span<const std::byte> wire,
                                         std::span<std::byte> dst) const;

    /* One-shot stream encrypt for callers holding the whole plaintext
     * in memory: a single FFI round trip through the Pipeline's
     * stream chain. For bounded-memory streaming use
     * encrypt_stream_pump or the incremental encrypt_stream_begin
     * session. */
    std::vector<std::uint8_t> encrypt_stream_one_shot(std::span<const std::byte> plain) const;

    /* Receive-side counterpart of encrypt_stream_one_shot. */
    std::vector<std::uint8_t> decrypt_stream_one_shot(std::span<const std::byte> wire) const;

    /* Reusable-buffer one-shot stream encrypt: writes the wire into
     * the caller-owned dst and returns the byte count written (same
     * buffer contract as encrypt_message_into). */
    std::size_t encrypt_stream_one_shot_into(std::span<const std::byte> plain,
                                             std::span<std::byte> dst) const;

    /* Receive-side counterpart of encrypt_stream_one_shot_into (same
     * buffer contract). After a failed call — MAC failure included —
     * the contents of dst are unspecified and must not be
     * interpreted. */
    std::size_t decrypt_stream_one_shot_into(std::span<const std::byte> wire,
                                             std::span<std::byte> dst) const;

    /* Opens an incremental encrypt session (plaintext in, wire out).
     * The session must not outlive its Pipeline. */
    EncryptStream encrypt_stream_begin() const;

    /* Receive-side counterpart (wire in, plaintext out). */
    DecryptStream decrypt_stream_begin() const;

    /* Zeroes the Pipeline's secret material Go-side and marks it
     * closed; subsequent cipher calls throw Status::TripleClosed.
     * Idempotent. The destructor calls it silently before releasing
     * the handle. */
    void close() noexcept;

private:
    Pipeline() = default;

    std::uintptr_t handle_ = 0;
    std::vector<std::uint8_t> blob_;
};

/* ------------------------------------------------------------------ */
/* Profile registration                                                */
/* ------------------------------------------------------------------ */

/* Registers a user-defined Triple profile under name; the opts follow
 * the register-profile grammar validated by Go. A duplicate name
 * throws Status::ProfileExists. */
void register_profile(std::string_view name, const Opts &opts);

/* ------------------------------------------------------------------ */
/* Runtime + diagnostics                                               */
/* ------------------------------------------------------------------ */

/* The libitb library version string (e.g. "0.3.1"). */
std::string version();

/* Sets the Go runtime's soft heap limit in bytes; returns the
 * previous limit. A negative value queries without changing. */
std::int64_t set_memory_limit(std::int64_t bytes) noexcept;

/* Sets the Go GC trigger percentage; returns the previous value. A
 * negative value queries without changing. */
int set_gc_percent(int pct) noexcept;

/* Diagnostic registry iteration for CLI tooling (the binding itself
 * performs no primitive-name validation or enumeration). */
std::size_t hash_count() noexcept;

/* Canonical name of the index-th shipped hash primitive; throws on an
 * out-of-range index. */
std::string hash_name(std::size_t index);

/* Native state width in bits of the index-th shipped hash primitive;
 * 0 when index is out of range. */
int hash_width(std::size_t index) noexcept;

} // namespace itb

#endif /* ITB_HPP */
