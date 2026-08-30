/*
 * pipeline.cpp — Triple Pipeline handle lifecycle plus the Single
 * Message cipher entries and profile registration.
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
/* init / open / lifecycle                                             */
/* ------------------------------------------------------------------ */

Pipeline Pipeline::init(std::string_view profile, const Opts &opts)
{
    const std::string prof(profile);
    std::vector<std::uint8_t> blob(detail::kBlobCap);
    std::size_t blob_len = 0;
    uintptr_t handle = 0;
    int rc = ITB_Triple_Init(ffi_str(prof), ffi_str(opts.query()),
                             blob.data(), blob.size(), &blob_len, &handle);
    if (rc == static_cast<int>(Status::BufferTooSmall) && blob_len > blob.size()) {
        /* Go closed the undersized attempt; the retry re-runs Init
         * and yields a fresh session. */
        blob.resize(blob_len);
        handle = 0;
        rc = ITB_Triple_Init(ffi_str(prof), ffi_str(opts.query()),
                             blob.data(), blob.size(), &blob_len, &handle);
    }
    check(rc, "Pipeline::init");
    blob.resize(blob_len);
    blob.shrink_to_fit();
    Pipeline pipe;
    pipe.handle_ = handle;
    pipe.blob_ = std::move(blob);
    return pipe;
}

Pipeline Pipeline::open(std::string_view profile,
                        std::span<const std::byte> blob,
                        const Opts &opts,
                        std::span<const std::byte> perm_master,
                        std::span<const std::byte> wrap_master)
{
    const std::string prof(profile);
    const bool perm_given = !perm_master.empty();
    const bool wrap_given = !wrap_master.empty();
    if (perm_given != wrap_given) {
        /* Half-supplied override pair. */
        fail(static_cast<int>(Status::BadInput), "Pipeline::open");
    }
    const std::size_t masters_count = perm_given ? 2 : 0;
    uintptr_t handle = 0;
    int rc = ITB_Triple_Open(ffi_str(prof),
                             ffi_bytes(blob), blob.size(),
                             ffi_str(opts.query()),
                             ffi_bytes(perm_master), perm_master.size(),
                             ffi_bytes(wrap_master), wrap_master.size(),
                             masters_count, &handle);
    check(rc, "Pipeline::open");
    Pipeline pipe;
    pipe.handle_ = handle;
    /* The Pipeline keeps its own copy of the blob for the accessor. */
    const auto *first = reinterpret_cast<const std::uint8_t *>(blob.data());
    pipe.blob_.assign(first, first + blob.size());
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

Pipeline::Pipeline(Pipeline &&other) noexcept
    : handle_(other.handle_), blob_(std::move(other.blob_))
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
        blob_ = std::move(other.blob_);
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
/* rekey                                                               */
/* ------------------------------------------------------------------ */

void Pipeline::rekey(std::span<const std::byte> perm_master,
                     std::span<const std::byte> wrap_master)
{
    std::vector<std::uint8_t> blob(
        blob_.size() > detail::kBlobCap ? blob_.size() : detail::kBlobCap);
    std::size_t blob_len = 0;
    int rc = ITB_Triple_Rekey(handle_,
                              ffi_bytes(perm_master), perm_master.size(),
                              ffi_bytes(wrap_master), wrap_master.size(),
                              blob.data(), blob.size(), &blob_len);
    if (rc == static_cast<int>(Status::BufferTooSmall) && blob_len > blob.size()) {
        blob.resize(blob_len);
        rc = ITB_Triple_Rekey(handle_,
                              ffi_bytes(perm_master), perm_master.size(),
                              ffi_bytes(wrap_master), wrap_master.size(),
                              blob.data(), blob.size(), &blob_len);
    }
    check(rc, "Pipeline::rekey");
    blob.resize(blob_len);
    blob.shrink_to_fit();
    blob_ = std::move(blob);
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
/* Profile registration                                                */
/* ------------------------------------------------------------------ */

void register_profile(std::string_view name, const Opts &opts)
{
    const std::string prof(name);
    check(ITB_Triple_RegisterProfile(ffi_str(prof), ffi_str(opts.query())),
          "register_profile");
}

} // namespace itb
