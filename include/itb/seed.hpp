// seed.hpp — RAII wrapper around `itb_seed_t`.
//
// Move-only RAII wrapper around the C binding's opaque seed handle.
// Two construction paths:
//
//     itb::Seed n{"blake3", 1024};                    // CSPRNG-keyed
//     itb::Seed n2 = itb::Seed::from_components(
//         "blake3", components_vec, hash_key_vec);   // deterministic
//
// Methods: width / hash_name / hash_key / components /
// attach_lock_seed. Destructor calls `itb_seed_free` best-effort.
//
// All three seeds passed to `itb::encrypt` / `itb::decrypt` (and the
// seven seeds passed to the Triple-Ouroboros counterparts) must
// share the same native hash width; mixing widths surfaces as
// `ItbError(STATUS_SEED_WIDTH_MIX)`.

#pragma once

#include <itb.h>
#include <itb/errors.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace itb {

class Seed {
public:
    // Construct a fresh seed with CSPRNG-generated keying material.
    // `hash_name` is one of the canonical hash primitives
    // (`"areion256"` / `"areion512"` / `"blake2b256"` / `"blake2b512"` /
    // `"blake2s"` / `"blake3"` / `"aescmac"` / `"siphash24"` /
    // `"chacha20"`); `key_bits` is the ITB key width in bits (512,
    // 1024, or 2048 — multiple of 64).
    Seed(std::string_view hash_name, int key_bits)
        : hash_name_{hash_name} {
        std::string nul_terminated{hash_name};
        int rc = itb_seed_new(nul_terminated.c_str(), key_bits, &handle_);
        if (rc != ITB_OK) {
            handle_ = nullptr;
            detail::throw_from_status(rc);
        }
    }

    // Build a seed deterministically from caller-supplied uint64
    // components and an optional fixed hash key. The canonical
    // persistence-restore path: pair `Seed::components()` and
    // `Seed::hash_key()` outputs with this constructor to rebuild a
    // seed across processes.
    //
    // `components` length must be 8..=32 (multiple of 8).
    // `hash_key` length, when non-empty, must match the primitive's
    // native fixed-key size: 16 (`aescmac`), 32 (`areion256` /
    // `blake2{s,b256}` / `blake3` / `chacha20`), 64 (`areion512` /
    // `blake2b512`). Pass an empty `hash_key` for `siphash24` or to
    // request a CSPRNG-generated key while keeping deterministic
    // components.
    static Seed from_components(std::string_view hash_name,
                                const std::vector<std::uint64_t>& components,
                                const std::vector<std::uint8_t>& hash_key) {
        std::string nul_terminated{hash_name};
        const std::uint8_t* key_ptr =
            hash_key.empty() ? nullptr : hash_key.data();
        const std::uint64_t* comp_ptr =
            components.empty() ? nullptr : components.data();
        itb_seed_t* h = nullptr;
        int rc = itb_seed_from_components(
            nul_terminated.c_str(),
            comp_ptr, components.size(),
            key_ptr, hash_key.size(),
            &h);
        if (rc != ITB_OK) {
            detail::throw_from_status(rc);
        }
        return Seed{h, std::string{hash_name}};
    }

    Seed(const Seed&) = delete;
    Seed& operator=(const Seed&) = delete;

    Seed(Seed&& other) noexcept
        : handle_{other.handle_},
          hash_name_{std::move(other.hash_name_)} {
        other.handle_ = nullptr;
    }

    Seed& operator=(Seed&& other) noexcept {
        if (this != &other) {
            release();
            handle_ = other.handle_;
            hash_name_ = std::move(other.hash_name_);
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~Seed() noexcept { release(); }

    // Returns the underlying C-binding handle. Exposed so other parts
    // of the C++ binding (cipher free functions, streams) can call
    // raw `itb_*` entry points without re-deriving the handle.
    itb_seed_t* raw_handle() const noexcept { return handle_; }

    // Returns the canonical hash name this seed was constructed with.
    std::string_view hash_name() const noexcept { return hash_name_; }

    int width() const {
        int w = 0;
        detail::check(itb_seed_width(handle_, &w));
        return w;
    }

    // Returns the seed's underlying uint64 components. Save these
    // alongside `hash_key()` for cross-process persistence —
    // `Seed::from_components` rebuilds the seed from the pair.
    std::vector<std::uint64_t> components() const {
        std::size_t cap = 0;
        int rc = itb_seed_components(handle_, nullptr, 0, &cap);
        if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
            detail::throw_from_status(rc);
        }
        if (cap == 0) {
            return {};
        }
        std::vector<std::uint64_t> out(cap);
        std::size_t got = 0;
        detail::check(itb_seed_components(handle_, out.data(), cap, &got));
        out.resize(got);
        return out;
    }

    // Returns the fixed key the underlying hash closure is bound to
    // (16 / 32 / 64 bytes depending on the primitive). `siphash24`
    // returns an empty vector — the primitive has no internal fixed
    // key (its keying material is the seed components themselves).
    std::vector<std::uint8_t> hash_key() const {
        std::size_t cap = 0;
        int rc = itb_seed_hash_key(handle_, nullptr, 0, &cap);
        if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
            detail::throw_from_status(rc);
        }
        if (cap == 0) {
            return {};
        }
        std::vector<std::uint8_t> out(cap);
        std::size_t got = 0;
        detail::check(itb_seed_hash_key(handle_, out.data(), cap, &got));
        out.resize(got);
        return out;
    }

    // Wires a dedicated lockSeed onto this noise seed. The lockSeed
    // has no observable effect on the wire output unless the
    // bit-permutation overlay is engaged via `itb::set_bit_soup(1)`
    // or `itb::set_lock_soup(1)` before the first encrypt / decrypt
    // call. Both seeds must share the same native hash width.
    //
    // Misuse paths surface as `ItbError(STATUS_BAD_INPUT)` (self-
    // attach, post-encrypt switching) or
    // `ItbError(STATUS_SEED_WIDTH_MIX)` (width mismatch).
    //
    // The lockSeed remains owned by the caller — attach only records
    // a pointer on the noise seed, so keep the lockSeed alive for
    // the lifetime of the noise seed.
    //
    // Threading. `attach_lock_seed` mutates the noise seed's internal
    // state (records the lockSeed pointer + invalidates the cached
    // PRF closure). It is NOT thread-safe — invoke it outside any
    // in-flight cipher call on the same noise seed, and outside any
    // other concurrent `attach_lock_seed` call against the same
    // noise seed. The call is the per-instance equivalent of a
    // process-wide setter: a single mutation, contracted to occur
    // before the first encrypt / decrypt on the seed.
    void attach_lock_seed(const Seed& lock) {
        detail::check(itb_seed_attach_lock_seed(handle_, lock.handle_));
    }

private:
    Seed(itb_seed_t* taken, std::string name) noexcept
        : handle_{taken}, hash_name_{std::move(name)} {}

    void release() noexcept {
        if (handle_ != nullptr) {
            itb_seed_free(handle_);
            handle_ = nullptr;
        }
    }

    itb_seed_t* handle_ = nullptr;
    std::string hash_name_;
};

} // namespace itb
