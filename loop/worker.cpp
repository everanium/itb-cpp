/*
 * The worker: its thread body (one warmup iteration, the warmup
 * barrier, the main loop), one iteration, the session pump loop the
 * stream shape drives, and the round-trip comparison that decides
 * between a worker error and a data mismatch.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include "loop.hpp"

namespace loop {

namespace {

constexpr const char *kShapeNames[] = {
    "stream", "message", "stream_one_shot", "both",
};

/* First offset at which a and b differ; the shorter length when one
 * is a prefix of the other. */
std::size_t first_difference(std::span<const std::uint8_t> a,
                             std::span<const std::uint8_t> b)
{
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    return n;
}

/* Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
 * has no bytes there. */
std::string hex_window(std::span<const std::uint8_t> buf, std::size_t off)
{
    if (off >= buf.size()) {
        return "-";
    }
    const std::size_t end = off + 16 < buf.size() ? off + 16 : buf.size();
    std::string out;
    for (std::size_t i = off; i < end; i++) {
        out += fmt("%02x", static_cast<unsigned>(buf[i]));
    }
    return out;
}

/* Records a worker error for a failed cipher call. stage names the
 * session step for a pump failure and is empty for a whole-buffer
 * call, whose only step is the direction itself. */
void cipher_fail(Worker &w, std::int64_t iter, Shape shape, const char *direction,
                 std::string_view stage, const itb::Error &e)
{
    if (stage.empty() || stage == direction) {
        worker_fail(w, fmt("g%d iter %lld shape=%s: %s: %s", w.id,
                           static_cast<long long>(iter), shape_name(shape), direction,
                           detail(e).c_str()));
    } else {
        worker_fail(w, fmt("g%d iter %lld shape=%s: %s: %.*s: %s", w.id,
                           static_cast<long long>(iter), shape_name(shape), direction,
                           static_cast<int>(stage.size()), stage.data(),
                           detail(e).c_str()));
    }
}

/* Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
 * and ITB drives the chunk loop internally; the C ABI has no reader /
 * writer entry, so the caller drives it: open a session, feed slices
 * of at most 1 MiB, drain whatever the session has produced after
 * every write (a read before end never blocks), end, then drain until
 * the session reports finished (after end, a read on an empty spool
 * blocks until the terminal bytes arrive). The whole produced output
 * lands in the worker's reusable accumulator. The loop is written
 * here rather than delegated to the binding's pump convenience so it
 * stands in the utility, at the same place, in every language.
 * Rethrows nothing: the failing step lands in stage. */
template <typename Session>
void pump_body(Worker &w, Session &session, std::span<const std::uint8_t> src,
               std::vector<std::uint8_t> &out, std::string_view &stage)
{
    const std::span<std::byte> drain =
        std::as_writable_bytes(std::span<std::uint8_t>(w.scratch));
    std::size_t off = 0;
    while (off < src.size()) {
        const std::size_t slice = src.size() - off < kPumpSlice ? src.size() - off : kPumpSlice;
        stage = "StreamWrite";
        session.write(std::as_bytes(src.subspan(off, slice)));
        off += slice;
        for (;;) {
            stage = "StreamRead";
            const itb::StreamRead got = session.read(drain);
            if (got.n == 0) {
                break;
            }
            out.insert(out.end(), w.scratch.begin(),
                       w.scratch.begin() + static_cast<std::ptrdiff_t>(got.n));
        }
    }
    stage = "StreamEnd";
    session.end();
    for (;;) {
        stage = "StreamRead";
        const itb::StreamRead got = session.read(drain);
        out.insert(out.end(), w.scratch.begin(),
                   w.scratch.begin() + static_cast<std::ptrdiff_t>(got.n));
        if (got.finished) {
            break;
        }
    }
}

bool pump(Worker &w, const itb::Pipeline &pipe, bool encrypt,
          std::span<const std::uint8_t> src, std::vector<std::uint8_t> &out,
          std::string_view &stage, std::optional<itb::Error> &err)
{
    out.clear();
    try {
        stage = "StreamBegin";
        if (encrypt) {
            itb::EncryptStream session = pipe.encrypt_stream_begin();
            pump_body(w, session, src, out, stage);
        } else {
            itb::DecryptStream session = pipe.decrypt_stream_begin();
            pump_body(w, session, src, out, stage);
        }
    } catch (const itb::Error &e) {
        err = e;
        return false;
    }
    return true;
}

/* One iteration. In order: refill the plaintext under rotating mode;
 * take the read lock; pick the surface; encrypt (timed); decrypt
 * (timed); compare the round-trip with the plaintext; bump the
 * counters; release the lock. The whole round-trip runs under the
 * read lock so handle-mutating maintenance (rekey, blob reopen) never
 * lands between an encrypt and its matching decrypt — maintenance
 * runs after this returns, from the worker loop. */
bool iterate(Worker &w, std::int64_t iter)
{
    RunState &r = *w.run;

    if (w.payload_mode == PayloadMode::Rotating) {
        if (!fill_payload(PayloadMode::Rotating, w.seeded, w.rng, w.plaintext)) {
            worker_fail(w, fmt("g%d iter %lld: payload refill: csprng", w.id,
                               static_cast<long long>(iter)));
            return false;
        }
    }

    const std::shared_lock<std::shared_mutex> guard(r.pipe_lock);

    /* Shape dispatch. message is one whole-buffer call on the Single
     * Message Pipeline; stream_one_shot is one whole-buffer call on
     * the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
     * which routes to the same one-shot stream entry the Go
     * harness calls by name); stream opens a session on the same
     * streaming Pipeline and drives the chunk loop from here. Under
     * both the three rotate by iteration number so the session path
     * and the whole-buffer path alternate on one handle inside every
     * worker — the cross-path state-reuse hazard this harness exists
     * to catch. */
    Shape shape = r.cfg.shape;
    if (shape == Shape::Both) {
        switch (iter % 3) {
        case 0:
            shape = Shape::Stream;
            break;
        case 1:
            shape = Shape::Message;
            break;
        default:
            shape = Shape::StreamOneShot;
            break;
        }
    }

    /* C++-specific. The message and one-shot entries return their own
     * vectors, released when the iteration ends; the pump accumulators
     * are the worker's own and are reused. */
    std::vector<std::uint8_t> owned_wire;
    std::vector<std::uint8_t> owned_plain;
    std::span<const std::uint8_t> got;
    std::string_view stage;
    std::optional<itb::Error> err;
    std::int64_t t0 = 0;

    const std::span<const std::uint8_t> plaintext(w.plaintext);

    switch (shape) {
    case Shape::Stream:
        t0 = now_ns();
        if (!pump(w, *r.stream_pipe, true, plaintext, w.wire, stage, err)) {
            cipher_fail(w, iter, shape, "encrypt", stage, *err);
            return false;
        }
        w.nanos_enc.fetch_add(now_ns() - t0);
        t0 = now_ns();
        if (!pump(w, *r.stream_pipe, false, w.wire, w.plain, stage, err)) {
            cipher_fail(w, iter, shape, "decrypt", stage, *err);
            return false;
        }
        w.nanos_dec.fetch_add(now_ns() - t0);
        got = std::span<const std::uint8_t>(w.plain);
        break;
    case Shape::StreamOneShot:
        try {
            t0 = now_ns();
            owned_wire = r.stream_pipe->encrypt_stream_one_shot(std::as_bytes(plaintext));
            w.nanos_enc.fetch_add(now_ns() - t0);
        } catch (const itb::Error &e) {
            cipher_fail(w, iter, shape, "encrypt", "", e);
            return false;
        }
        try {
            t0 = now_ns();
            owned_plain = r.stream_pipe->decrypt_stream_one_shot(itb::as_bytes(owned_wire));
            w.nanos_dec.fetch_add(now_ns() - t0);
        } catch (const itb::Error &e) {
            cipher_fail(w, iter, shape, "decrypt", "", e);
            return false;
        }
        got = std::span<const std::uint8_t>(owned_plain);
        break;
    case Shape::Message:
        try {
            t0 = now_ns();
            owned_wire = r.msg_pipe->encrypt_message(std::as_bytes(plaintext));
            w.nanos_enc.fetch_add(now_ns() - t0);
        } catch (const itb::Error &e) {
            cipher_fail(w, iter, shape, "encrypt", "", e);
            return false;
        }
        try {
            t0 = now_ns();
            owned_plain = r.msg_pipe->decrypt_message(itb::as_bytes(owned_wire));
            w.nanos_dec.fetch_add(now_ns() - t0);
        } catch (const itb::Error &e) {
            cipher_fail(w, iter, shape, "decrypt", "", e);
            return false;
        }
        got = std::span<const std::uint8_t>(owned_plain);
        break;
    case Shape::Both:
        break; /* resolved above */
    }

    /* Failure model. A cipher call that returns a non-OK status is a
     * worker error: it is recorded, the run is asked to stop, the
     * other workers finish their in-flight iteration, and the error
     * is listed in the summary with the FAIL verdict. A round-trip
     * that returns OK with different bytes is a data mismatch: the
     * process terminates here, without summary or cleanup, because
     * the Pipeline state that produced the wrong bytes is the
     * evidence and nothing that runs afterwards may touch it. */
    if (got.size() != plaintext.size()
        || std::memcmp(plaintext.data(), got.data(), plaintext.size()) != 0) {
        const std::size_t off = first_difference(plaintext, got);
        err_line(fmt("DATA MISMATCH g%d iter %lld shape=%s: want %zu bytes, got %zu bytes, "
                     "first difference at offset %zu: want %s got %s",
                     w.id, static_cast<long long>(iter), shape_name(shape),
                     plaintext.size(), got.size(), off,
                     hex_window(plaintext, off).c_str(), hex_window(got, off).c_str()));
        std::_Exit(3);
    }

    w.iters.fetch_add(1);
    w.bytes_enc.fetch_add(static_cast<std::int64_t>(plaintext.size()));
    w.bytes_dec.fetch_add(static_cast<std::int64_t>(got.size()));
    return true;
}

/* Marks this worker returned; the last one to return stamps the
 * finish instant and wakes main. */
void worker_done(RunState &r)
{
    const std::lock_guard<std::mutex> guard(r.done_mu);
    r.active--;
    if (r.active == 0) {
        r.finish_ns = now_ns();
        r.done_cv.notify_one();
    }
}

} // namespace

const char *shape_name(Shape shape)
{
    return kShapeNames[static_cast<std::size_t>(shape)];
}

bool parse_shape(std::string_view s, Shape &out)
{
    for (std::size_t i = 0; i < std::size(kShapeNames); i++) {
        if (s == kShapeNames[i]) {
            out = static_cast<Shape>(i);
            return true;
        }
    }
    return false;
}

/* Records the worker's error text (first error wins) and requests a
 * stop of the whole run. */
void worker_fail(Worker &w, std::string text)
{
    if (!w.failed) {
        w.error = std::move(text);
        w.failed = true;
    }
    w.run->stop.store(true);
}

/* The worker thread body: one warmup iteration, the warmup barrier,
 * then the main loop until a stop is requested or the fixed
 * per-worker iteration budget (warmup included) is spent. A failing
 * warmup still passes both barriers so the launcher never waits on a
 * worker that has already given up. */
void worker_main(Worker *wp)
{
    Worker &w = *wp;
    RunState &r = *w.run;

    /* Warmup iteration — counted in the totals; its completion feeds
     * the post-warmup baselines. */
    const bool ok = iterate(w, 0);
    r.warmup_done->arrive_and_wait();
    r.release->arrive_and_wait();
    if (!ok) {
        worker_done(r);
        return;
    }

    for (std::int64_t iter = 1;; iter++) {
        if (r.cfg.iterations > 0 && iter >= r.cfg.iterations) {
            break;
        }
        if (r.stop.load()) {
            break;
        }
        if (!iterate(w, iter)) {
            break;
        }
        if (!worker_maintenance(w, iter)) {
            break;
        }
    }
    worker_done(r);
}

} // namespace loop
