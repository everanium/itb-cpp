// mac.hpp — RAII wrapper around `itb_mac_t`.
//
// Move-only RAII wrapper around the C binding's opaque MAC handle.
// Used with the authenticated encrypt / decrypt entry points in
// `<itb/cipher.hpp>` — `Encryptor` instances keep their own bound
// MAC and do not interact with this class directly.
//
// Construct via:
//
//     itb::Mac m{"hmac-blake3", key_bytes};
//
// Key length must satisfy the primitive's minimum (16 bytes for
// `kmac256` / `hmac-sha256`, 32 bytes for `hmac-blake3`).

#pragma once

#include <itb.h>
#include <itb/errors.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace itb {

class Mac {
public:
    Mac(std::string_view mac_name, const std::vector<std::uint8_t>& key)
        : name_{mac_name} {
        std::string nul_terminated{mac_name};
        const std::uint8_t* key_ptr = key.empty() ? nullptr : key.data();
        int rc = itb_mac_new(nul_terminated.c_str(),
                             key_ptr, key.size(), &handle_);
        if (rc != ITB_OK) {
            handle_ = nullptr;
            detail::throw_from_status(rc);
        }
    }

    Mac(const Mac&) = delete;
    Mac& operator=(const Mac&) = delete;

    Mac(Mac&& other) noexcept
        : handle_{other.handle_}, name_{std::move(other.name_)} {
        other.handle_ = nullptr;
    }

    Mac& operator=(Mac&& other) noexcept {
        if (this != &other) {
            release();
            handle_ = other.handle_;
            name_ = std::move(other.name_);
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~Mac() noexcept { release(); }

    itb_mac_t* raw_handle() const noexcept { return handle_; }

    std::string_view name() const noexcept { return name_; }

private:
    void release() noexcept {
        if (handle_ != nullptr) {
            itb_mac_free(handle_);
            handle_ = nullptr;
        }
    }

    itb_mac_t* handle_ = nullptr;
    std::string name_;
};

} // namespace itb
