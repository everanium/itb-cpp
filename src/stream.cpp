/*
 * stream.cpp — incremental stream sessions over an open Pipeline
 * plus the whole-buffer pump conveniences.
 *
 * A session is a dumb byte pump: plaintext (or wire) goes in through
 * write, produced bytes come out through read. All chunking, MAC,
 * envelope, and wire-format decisions stay inside libitb — the
 * binding moves opaque bytes and relays status codes.
 */

#include <algorithm>
#include <memory>

#include "internal.hpp"

namespace itb {

using detail::check;
using detail::ffi_bytes;

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                   */
/* ------------------------------------------------------------------ */

EncryptStream Pipeline::encrypt_stream_begin() const
{
    uintptr_t handle = 0;
    check(ITB_Triple_EncryptStreamBegin(handle_, &handle),
          "Pipeline::encrypt_stream_begin");
    return EncryptStream(handle);
}

DecryptStream Pipeline::decrypt_stream_begin() const
{
    uintptr_t handle = 0;
    check(ITB_Triple_DecryptStreamBegin(handle_, &handle),
          "Pipeline::decrypt_stream_begin");
    return DecryptStream(handle);
}

void Stream::write(std::span<const std::byte> src)
{
    check(ITB_Triple_StreamWrite(handle_, ffi_bytes(src), src.size()),
          "Stream::write");
}

void Stream::end()
{
    check(ITB_Triple_StreamEnd(handle_), "Stream::end");
}

StreamRead Stream::read(std::span<std::byte> dst)
{
    std::size_t n = 0;
    int fin = 0;
    check(ITB_Triple_StreamRead(handle_, ffi_bytes(dst), dst.size(), &n, &fin),
          "Stream::read");
    return {n, fin != 0};
}

void Stream::close() noexcept
{
    if (handle_ != 0) {
        /* StreamFree cancels and releases from any state, wiping the
         * Go-side spool; the status is deliberately ignored on the
         * release path. */
        (void)ITB_Triple_StreamFree(handle_);
        handle_ = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Whole-buffer pumps                                                  */
/* ------------------------------------------------------------------ */

namespace {

/* Canonical pump: feed bounded slices, draining the spool after each
 * write straight into dst's free tail → end → drain until finished.
 * Zero intermediate copies — every read lands directly in the
 * caller-owned dst; the byte count written is returned. A dst too
 * small for the produced output throws std::invalid_argument (the
 * bound check doubles as the write ceiling: every read's cap is the
 * remaining tail of dst, never more). */
std::size_t pump_into(Stream &session, std::span<const std::byte> src,
                      std::span<std::byte> dst)
{
    std::size_t used = 0;

    const auto drain_one = [&]() -> StreamRead {
        if (used == dst.size()) {
            /* dst has no free tail — the produced output is larger
             * than the caller-supplied buffer. The Go-side
             * TripleStreamRead synchronises the finished flag with
             * the cipher goroutine's close(done) teardown step, so
             * the read that consumes the last bytes reports
             * finished == true in the same call; an exact-size dst
             * therefore never lands here on a well-formed pump. */
            throw std::invalid_argument(
                "itb: stream pump dst too small for the produced output; "
                "size it via itb::out_bound");
        }
        const StreamRead r = session.read(dst.subspan(used));
        if (r.n > dst.size() - used) {
            /* Bounds sanity on the FFI-reported drain length; an
             * out-of-range count must never advance the cursor. */
            detail::fail(static_cast<int>(Status::Internal), "stream pump read");
        }
        used += r.n;
        return r;
    };

    std::size_t offset = 0;
    while (offset < src.size()) {
        const std::size_t slice = std::min(src.size() - offset, detail::kPumpBuf);
        session.write(src.subspan(offset, slice));
        offset += slice;
        /* Drain whatever the chain has produced so far; a read before
         * end never blocks. */
        while (drain_one().n != 0) {
        }
    }

    session.end();
    while (!drain_one().finished) {
    }
    return used;
}

/* Exact-size wrapper over pump_into: uninitialised scratch at the
 * expansion bound, one full pump, one exact-length copy into the
 * returned vector. Should libitb ever outproduce the bound, the
 * whole pump is retried on a fresh session with a doubled buffer (a
 * never-in-practice fallback; nothing has been handed out yet, so
 * the restart is invisible to the caller). */
template <typename BeginFn>
std::vector<std::uint8_t> pump_alloc(BeginFn &&begin, std::span<const std::byte> src)
{
    std::size_t cap = detail::out_cap(src.size());
    for (int attempt = 0;; ++attempt) {
        auto buf = std::make_unique_for_overwrite<std::uint8_t[]>(cap);
        auto session = begin();
        try {
            const std::size_t n = pump_into(
                session, src, {reinterpret_cast<std::byte *>(buf.get()), cap});
            return std::vector<std::uint8_t>(buf.get(), buf.get() + n);
        } catch (const std::invalid_argument &) {
            if (attempt >= 2 || cap > (SIZE_MAX >> 1)) {
                throw;
            }
            cap *= 2;
        }
    }
}

} // namespace

std::vector<std::uint8_t> Pipeline::encrypt_stream_pump(std::span<const std::byte> plain) const
{
    return pump_alloc([this] { return encrypt_stream_begin(); }, plain);
}

std::vector<std::uint8_t> Pipeline::decrypt_stream_pump(std::span<const std::byte> wire) const
{
    return pump_alloc([this] { return decrypt_stream_begin(); }, wire);
}

std::size_t Pipeline::encrypt_stream_pump_into(std::span<const std::byte> plain,
                                               std::span<std::byte> dst) const
{
    EncryptStream session = encrypt_stream_begin();
    return pump_into(session, plain, dst);
}

std::size_t Pipeline::decrypt_stream_pump_into(std::span<const std::byte> wire,
                                               std::span<std::byte> dst) const
{
    DecryptStream session = decrypt_stream_begin();
    return pump_into(session, wire, dst);
}

} // namespace itb
