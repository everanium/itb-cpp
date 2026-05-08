// library.hpp — process-wide library helpers.
//
// Free functions in the `itb` namespace covering the process-global
// surface: version / max key bits / channel count / chunk-header
// size / process-wide setters / hash + MAC registries.
//
// Threading caveat for setters. Each individual setter is atomic on
// the libitb side (`atomic.Int32.Store`) and safe to call from any
// thread in isolation. The caveat is logical, not atomic: changing
// any of these knobs while an encrypt / decrypt call is in flight
// corrupts the running operation, because the cipher snapshots its
// configuration at call entry and a mid-flight change breaks the
// running invariants. Treat the global knobs as set-once-at-startup;
// rare runtime updates need external sequencing against active
// cipher calls.

#pragma once

#include <itb.h>
#include <itb/encryptor.hpp>  // for detail::read_two_call_string
#include <itb/errors.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace itb {

// ---- Library version + capability accessors ----------------------

inline std::string version() {
    return detail::read_two_call_string(
        [](char* buf, std::size_t cap, std::size_t* out_len) {
            return itb_version(buf, cap, out_len);
        });
}

inline int max_key_bits() noexcept { return itb_max_key_bits(); }

inline int channels() noexcept { return itb_channels(); }

inline int header_size() noexcept { return itb_header_size(); }

inline std::size_t parse_chunk_len(const std::uint8_t* header,
                                   std::size_t len) {
    std::size_t out = 0;
    detail::check(itb_parse_chunk_len(header, len, &out));
    return out;
}

inline std::size_t parse_chunk_len(const std::vector<std::uint8_t>& header) {
    return parse_chunk_len(header.data(), header.size());
}

// ---- Hash registry -----------------------------------------------

struct HashEntry {
    std::string name;
    int width = 0;
};

inline std::vector<HashEntry> list_hashes() {
    int n = itb_hash_count();
    std::vector<HashEntry> out;
    if (n <= 0) {
        return out;
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        HashEntry e;
        e.name = detail::read_two_call_string(
            [i](char* buf, std::size_t cap, std::size_t* out_len) {
                return itb_hash_name(i, buf, cap, out_len);
            });
        e.width = itb_hash_width(i);
        out.push_back(std::move(e));
    }
    return out;
}

// ---- MAC registry ------------------------------------------------

struct MacEntry {
    std::string name;
    int key_size = 0;
    int tag_size = 0;
    int min_key_bytes = 0;
};

inline std::vector<MacEntry> list_macs() {
    int n = itb_mac_count();
    std::vector<MacEntry> out;
    if (n <= 0) {
        return out;
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        MacEntry e;
        e.name = detail::read_two_call_string(
            [i](char* buf, std::size_t cap, std::size_t* out_len) {
                return itb_mac_name(i, buf, cap, out_len);
            });
        e.key_size = itb_mac_key_size(i);
        e.tag_size = itb_mac_tag_size(i);
        e.min_key_bytes = itb_mac_min_key_bytes(i);
        out.push_back(std::move(e));
    }
    return out;
}

// ---- Process-wide setters / getters ------------------------------

inline void set_bit_soup(int mode) {
    detail::check(itb_set_bit_soup(mode));
}
inline int get_bit_soup() noexcept { return itb_get_bit_soup(); }

inline void set_lock_soup(int mode) {
    detail::check(itb_set_lock_soup(mode));
}
inline int get_lock_soup() noexcept { return itb_get_lock_soup(); }

inline void set_max_workers(int n) {
    detail::check(itb_set_max_workers(n));
}
inline int get_max_workers() noexcept { return itb_get_max_workers(); }

// Accepts 128, 256, or 512.
inline void set_nonce_bits(int n) {
    detail::check(itb_set_nonce_bits(n));
}
inline int get_nonce_bits() noexcept { return itb_get_nonce_bits(); }

// Accepts 1, 2, 4, 8, 16, or 32.
inline void set_barrier_fill(int n) {
    detail::check(itb_set_barrier_fill(n));
}
inline int get_barrier_fill() noexcept { return itb_get_barrier_fill(); }

} // namespace itb
