/*
 * pipeline.cpp — Triple Pipeline handle lifecycle, persistence
 * (save / load), the Single Message cipher entries, and the profile
 * record entries (inspect / register_profile / lookup / profiles).
 *
 * Binding-side logic is limited to the four FFI-boundary inversions:
 * caller-allocated buffers with the codified retry-once on
 * Status::BufferTooSmall, RAII handle release, byte transport, and
 * status relay. Everything else — validation, profile catalogue,
 * wire format, MAC handling — is Go's job.
 */

#include <memory>

#include "internal.hpp"

namespace itb {

using detail::check;
using detail::fail;
using detail::ffi_bytes;
using detail::ffi_str;

/* ------------------------------------------------------------------ */
/* Caller-allocated-buffer helper                                      */
/* ------------------------------------------------------------------ */

namespace {

/* Single retry-once dispatch site for every variable-size output
 * buffer (init / rekey / save / inspect / lookup / profiles):
 * pre-allocate kBlobCap, and on Status::BufferTooSmall retry once
 * with the exact size libitb reported. */
template <typename Fn>
std::vector<std::uint8_t> buf_call(Fn &&fn, const char *what)
{
    std::vector<std::uint8_t> buf(detail::kBlobCap);
    std::size_t n = 0;
    int rc = fn(buf.data(), buf.size(), &n);
    if (rc == static_cast<int>(Status::BufferTooSmall) && n > buf.size()) {
        buf.resize(n);
        rc = fn(buf.data(), buf.size(), &n);
    }
    check(rc, what);
    if (n > buf.size()) {
        fail(static_cast<int>(Status::Internal), what);
    }
    buf.resize(n);
    buf.shrink_to_fit();
    return buf;
}

std::string json_call(std::vector<std::uint8_t> bytes)
{
    return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

/* The masters pair crosses as (perm, wrap, count): both absent → 0,
 * otherwise 2 — libitb validates the pair. */
std::size_t masters_count(std::span<const std::byte> perm,
                          std::span<const std::byte> wrap) noexcept
{
    return (perm.empty() && wrap.empty()) ? 0 : 2;
}

} // namespace

/* ------------------------------------------------------------------ */
/* init / load / lifecycle                                             */
/* ------------------------------------------------------------------ */

Pipeline Pipeline::init(std::string_view profile, const Opts &opts)
{
    const std::string prof(profile);
    uintptr_t handle = 0;
    /* The init blob is not retained binding-side; save() reads the
     * current bytes from libitb. On a buffer retry Go closes the
     * undersized attempt and the re-run yields a fresh session. */
    (void)buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            handle = 0;
            return ITB_Triple_Init(ffi_str(prof), ffi_str(opts.query()),
                                   out, cap, len, &handle);
        },
        "Pipeline::init");
    Pipeline pipe;
    pipe.handle_ = handle;
    return pipe;
}

Pipeline Pipeline::load(std::span<const std::byte> blob,
                        std::span<const std::byte> perm_master,
                        std::span<const std::byte> wrap_master)
{
    uintptr_t handle = 0;
    int rc = ITB_Triple_Load(ffi_bytes(blob), blob.size(),
                             ffi_bytes(perm_master), perm_master.size(),
                             ffi_bytes(wrap_master), wrap_master.size(),
                             masters_count(perm_master, wrap_master), &handle);
    check(rc, "Pipeline::load");
    Pipeline pipe;
    pipe.handle_ = handle;
    return pipe;
}

Pipeline Pipeline::load_f(std::string_view path,
                          std::span<const std::byte> perm_master,
                          std::span<const std::byte> wrap_master)
{
    const std::string p(path);
    uintptr_t handle = 0;
    int rc = ITB_Triple_LoadF(ffi_str(p),
                              ffi_bytes(perm_master), perm_master.size(),
                              ffi_bytes(wrap_master), wrap_master.size(),
                              masters_count(perm_master, wrap_master), &handle);
    check(rc, "Pipeline::load_f");
    Pipeline pipe;
    pipe.handle_ = handle;
    return pipe;
}

Pipeline::~Pipeline()
{
    if (handle_ != 0) {
        /* Free runs Close first Go-side (zeroing key material); the
         * status is deliberately ignored on the release path. */
        (void)ITB_Triple_Free(handle_);
        handle_ = 0;
    }
}

Pipeline::Pipeline(Pipeline &&other) noexcept : handle_(other.handle_)
{
    other.handle_ = 0;
}

Pipeline &Pipeline::operator=(Pipeline &&other) noexcept
{
    if (this != &other) {
        if (handle_ != 0) {
            (void)ITB_Triple_Free(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = 0;
    }
    return *this;
}

void Pipeline::close() noexcept
{
    if (handle_ != 0) {
        /* Idempotent Go-side; the handle stays valid until the
         * destructor releases it. */
        (void)ITB_Triple_Close(handle_);
    }
}

/* ------------------------------------------------------------------ */
/* save / max_workers / rekey                                          */
/* ------------------------------------------------------------------ */

std::vector<std::uint8_t> Pipeline::save() const
{
    return buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            return ITB_Triple_Save(handle_, out, cap, len);
        },
        "Pipeline::save");
}

void Pipeline::save_f(std::string_view path) const
{
    const std::string p(path);
    check(ITB_Triple_SaveF(handle_, ffi_str(p)), "Pipeline::save_f");
}

void Pipeline::max_workers(int n) const
{
    check(ITB_Triple_MaxWorkers(handle_, n), "Pipeline::max_workers");
}

std::vector<std::uint8_t> Pipeline::rekey(std::span<const std::byte> perm_master,
                                          std::span<const std::byte> wrap_master)
{
    return buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            return ITB_Triple_Rekey(handle_,
                                    ffi_bytes(perm_master), perm_master.size(),
                                    ffi_bytes(wrap_master), wrap_master.size(),
                                    out, cap, len);
        },
        "Pipeline::rekey");
}

/* ------------------------------------------------------------------ */
/* Single Message encrypt / decrypt                                    */
/* ------------------------------------------------------------------ */

namespace {

/* Shared body for the buffer-in / buffer-out cipher entries: single
 * retry-once dispatch over the caller-allocated-buffer convention. */
using CipherFn = int (*)(uintptr_t handle, void *src, size_t src_len,
                         void *out, size_t out_cap, size_t *out_len);

std::vector<std::uint8_t> cipher_call(uintptr_t handle, CipherFn fn,
                                      std::span<const std::byte> src,
                                      const char *what)
{
    /* Uninitialised scratch at the expansion bound: the cap-wide
     * zero-fill a std::vector constructor would perform is pure waste
     * (libitb overwrites the prefix, the tail is discarded). One
     * exact-size copy into the returned vector at the end. */
    std::size_t cap = detail::out_cap(src.size());
    auto buf = std::make_unique_for_overwrite<std::uint8_t[]>(cap);
    std::size_t n = 0;
    int rc = fn(handle, ffi_bytes(src), src.size(), buf.get(), cap, &n);
    if (rc == static_cast<int>(Status::BufferTooSmall) && n > cap) {
        cap = n;
        buf = std::make_unique_for_overwrite<std::uint8_t[]>(cap);
        rc = fn(handle, ffi_bytes(src), src.size(), buf.get(), cap, &n);
    }
    check(rc, what);
    if (n > cap) {
        fail(static_cast<int>(Status::Internal), what);
    }
    return std::vector<std::uint8_t>(buf.get(), buf.get() + n);
}

/* Reusable-buffer body shared by the *_into cipher entries: one FFI
 * call writing straight into the caller-owned dst. The FFI write
 * ceiling (out_cap argument) is dst.size() itself, so the call can
 * never write past the caller's buffer; an undersized dst surfaces
 * as Status::BufferTooSmall relayed through check (no retry — the
 * caller owns sizing via itb::out_bound). */
std::size_t cipher_call_into(uintptr_t handle, CipherFn fn,
                             std::span<const std::byte> src,
                             std::span<std::byte> dst, const char *what)
{
    std::size_t n = 0;
    int rc = fn(handle, ffi_bytes(src), src.size(),
                detail::ffi_bytes(dst), dst.size(), &n);
    check(rc, what);
    if (n > dst.size()) {
        /* Bounds sanity on the FFI-reported length; an out-of-range
         * count must never reach the caller. */
        fail(static_cast<int>(Status::Internal), what);
    }
    return n;
}

} // namespace

std::vector<std::uint8_t> Pipeline::encrypt_message(std::span<const std::byte> plain) const
{
    return cipher_call(handle_, ITB_Triple_EncryptMessage, plain,
                       "Pipeline::encrypt_message");
}

std::vector<std::uint8_t> Pipeline::decrypt_message(std::span<const std::byte> wire) const
{
    return cipher_call(handle_, ITB_Triple_DecryptMessage, wire,
                       "Pipeline::decrypt_message");
}

std::size_t Pipeline::encrypt_message_into(std::span<const std::byte> plain,
                                           std::span<std::byte> dst) const
{
    return cipher_call_into(handle_, ITB_Triple_EncryptMessage, plain, dst,
                            "Pipeline::encrypt_message_into");
}

std::size_t Pipeline::decrypt_message_into(std::span<const std::byte> wire,
                                           std::span<std::byte> dst) const
{
    return cipher_call_into(handle_, ITB_Triple_DecryptMessage, wire, dst,
                            "Pipeline::decrypt_message_into");
}

/* ------------------------------------------------------------------ */
/* One-shot stream encrypt / decrypt                                   */
/* ------------------------------------------------------------------ */
/* Whole-buffer stream entries in a single FFI round trip: the
 * streaming wiring runs inside libitb, so the buffer-in / buffer-out
 * dispatch is identical to the Single Message pair. */

std::vector<std::uint8_t> Pipeline::encrypt_stream_one_shot(std::span<const std::byte> plain) const
{
    return cipher_call(handle_, ITB_Triple_EncryptStream, plain,
                       "Pipeline::encrypt_stream_one_shot");
}

std::vector<std::uint8_t> Pipeline::decrypt_stream_one_shot(std::span<const std::byte> wire) const
{
    return cipher_call(handle_, ITB_Triple_DecryptStream, wire,
                       "Pipeline::decrypt_stream_one_shot");
}

std::size_t Pipeline::encrypt_stream_one_shot_into(std::span<const std::byte> plain,
                                                   std::span<std::byte> dst) const
{
    return cipher_call_into(handle_, ITB_Triple_EncryptStream, plain, dst,
                            "Pipeline::encrypt_stream_one_shot_into");
}

std::size_t Pipeline::decrypt_stream_one_shot_into(std::span<const std::byte> wire,
                                                   std::span<std::byte> dst) const
{
    return cipher_call_into(handle_, ITB_Triple_DecryptStream, wire, dst,
                            "Pipeline::decrypt_stream_one_shot_into");
}

/* ------------------------------------------------------------------ */
/* Profile records: inspect / register_profile / lookup / profiles     */
/* ------------------------------------------------------------------ */

std::string inspect(std::span<const std::byte> blob)
{
    return json_call(buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            return ITB_Triple_Inspect(ffi_bytes(blob), blob.size(), out, cap, len);
        },
        "inspect"));
}

void register_profile(std::string_view name, std::string_view profile_json)
{
    const std::string n(name);
    const std::string json(profile_json);
    check(ITB_Triple_Register(ffi_str(n), ffi_str(json)), "register_profile");
}

std::string lookup(std::string_view name)
{
    const std::string n(name);
    return json_call(buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            return ITB_Triple_Lookup(ffi_str(n), out, cap, len);
        },
        "lookup"));
}

std::string profiles()
{
    return json_call(buf_call(
        [&](void *out, std::size_t cap, std::size_t *len) {
            return ITB_Triple_Profiles(out, cap, len);
        },
        "profiles"));
}

} // namespace itb
