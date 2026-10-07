/*
 * The maintenance operations that mutate a live Pipeline handle
 * between iterations: master rotation (--rekey-every) and blob
 * reopen (--blob-cycle-every).
 */

#include <array>
#include <cstdint>
#include <mutex>
#include <string>

#include "loop.hpp"

namespace loop {

namespace {

/* Byte length of each fresh master drawn for a rotation. Matches the
 * size Init auto-generates for both the parallax and the wrapper
 * master. */
constexpr std::size_t kRekeyMasterSize = 32;

/* Master rotation. Rotates the parallax + wrapper masters on every
 * active Pipeline under the write lock and retains the refreshed
 * blob for subsequent blob reopens. Masters are drawn fresh from the
 * OS CSPRNG on every rotation regardless of --seed (master rotation
 * is pipeline keying, not plaintext content); a disabled layer passes
 * no bytes, which Rekey ignores. The eight inner seeds and the MAC
 * key are untouched by design — Rekey targets only the two
 * outer-layer master secrets. */
bool rekey_pipes(Worker &w, std::int64_t iter)
{
    RunState &r = *w.run;
    std::array<std::uint8_t, kRekeyMasterSize> perm{};
    std::array<std::uint8_t, kRekeyMasterSize> wrap{};
    std::span<const std::byte> perm_view;
    std::span<const std::byte> wrap_view;

    if (r.cfg.parallax) {
        if (!fill_random(perm)) {
            worker_fail(w, fmt("g%d iter %lld: csprng: parallax master", w.id,
                               static_cast<long long>(iter)));
            return false;
        }
        perm_view = std::as_bytes(std::span<const std::uint8_t>(perm));
    }
    if (r.cfg.wrapper) {
        if (!fill_random(wrap)) {
            worker_fail(w, fmt("g%d iter %lld: csprng: wrapper master", w.id,
                               static_cast<long long>(iter)));
            return false;
        }
        wrap_view = std::as_bytes(std::span<const std::uint8_t>(wrap));
    }

    const std::lock_guard<std::shared_mutex> guard(r.pipe_lock);
    if (r.stream_pipe.has_value()) {
        try {
            r.stream_blob = r.stream_pipe->rekey(perm_view, wrap_view);
        } catch (const itb::Error &e) {
            worker_fail(w, fmt("g%d iter %lld: Rekey(%s): %s", w.id,
                               static_cast<long long>(iter), r.stream_profile.c_str(),
                               detail(e).c_str()));
            return false;
        }
    }
    if (r.msg_pipe.has_value()) {
        try {
            r.msg_blob = r.msg_pipe->rekey(perm_view, wrap_view);
        } catch (const itb::Error &e) {
            worker_fail(w, fmt("g%d iter %lld: Rekey(%s): %s", w.id,
                               static_cast<long long>(iter), r.msg_profile.c_str(),
                               detail(e).c_str()));
            return false;
        }
    }
    const long long n = static_cast<long long>(r.rekeys.fetch_add(1)) + 1;
    log_line(fmt("rekey: g%d iter %lld rotated parallax + wrapper masters (rekey #%lld)",
                 w.id, static_cast<long long>(iter), n));
    return true;
}

/* Blob reopen. Reopens every active Pipeline from its retained blob
 * under the write lock: a fresh handle is loaded from the blob, the
 * running handle is freed, and the fresh one is swapped in, so every
 * later iteration round-trips through seeds and masters that survived
 * a blob crossing. The input is the blob Init or the latest Rekey
 * handed out, not a fresh Save: that is what a receiver holds, and
 * reopening from it proves the handed-out bytes rather than the live
 * state. The blob carries the Pipeline's full shape, so no override
 * reaches the reopen. On a Load failure the running handle stays and
 * the failure aborts the run. */
bool blob_cycle_pipes(Worker &w, std::int64_t iter)
{
    RunState &r = *w.run;
    const std::lock_guard<std::shared_mutex> guard(r.pipe_lock);
    if (r.stream_pipe.has_value()) {
        try {
            /* C++-specific. Move-assignment into the optional destroys
             * the running handle only after the fresh one has been
             * constructed, so a throwing Load leaves it in place. */
            itb::Pipeline fresh = itb::Pipeline::load(itb::as_bytes(r.stream_blob));
            r.stream_pipe = std::move(fresh);
        } catch (const itb::Error &e) {
            worker_fail(w, fmt("g%d iter %lld: Load(%s): %s", w.id,
                               static_cast<long long>(iter), r.stream_profile.c_str(),
                               detail(e).c_str()));
            return false;
        }
    }
    if (r.msg_pipe.has_value()) {
        try {
            itb::Pipeline fresh = itb::Pipeline::load(itb::as_bytes(r.msg_blob));
            r.msg_pipe = std::move(fresh);
        } catch (const itb::Error &e) {
            worker_fail(w, fmt("g%d iter %lld: Load(%s): %s", w.id,
                               static_cast<long long>(iter), r.msg_profile.c_str(),
                               detail(e).c_str()));
            return false;
        }
    }
    const long long n = static_cast<long long>(r.blob_cycles.fetch_add(1)) + 1;
    log_line(fmt("blob-cycle: g%d iter %lld reopened from session blob (cycle #%lld)",
                 w.id, static_cast<long long>(iter), n));
    return true;
}

} // namespace

/* Handle mutation. Runs the periodic Pipeline-mutating operations
 * after a completed iteration: master rotation (--rekey-every) and
 * blob reopen (--blob-cycle-every). Both intervals count per-worker
 * iterations; the warmup iteration (iter 0) never triggers because
 * the worker loop calls this for iter >= 1 only. Rekey rewrites the
 * outer-layer keying of a live handle and a blob reopen replaces the
 * handle outright; each takes the write lock, so in-flight cipher
 * calls on other workers drain before anything changes and no
 * encrypt is separated from its decrypt by either. Returns false
 * after recording the worker error. */
bool worker_maintenance(Worker &w, std::int64_t iter)
{
    const Config &cfg = w.run->cfg;
    if (cfg.rekey_every > 0 && iter % cfg.rekey_every == 0) {
        if (!rekey_pipes(w, iter)) {
            return false;
        }
    }
    if (cfg.blob_cycle_every > 0 && iter % cfg.blob_cycle_every == 0) {
        if (!blob_cycle_pipes(w, iter)) {
            return false;
        }
    }
    return true;
}

} // namespace loop
