/*
 * runtime.cpp — Go runtime knobs, library version, and the
 * diagnostic registry iteration for CLI tooling.
 */

#include <array>
#include <climits>

#include "internal.hpp"

namespace itb {

std::string version()
{
    std::array<char, 64> buf{};
    std::size_t need = 0;
    detail::check(ITB_Version(buf.data(), buf.size(), &need), "version");
    return {buf.data()};
}

std::int64_t set_memory_limit(std::int64_t bytes) noexcept
{
    return ITB_SetMemoryLimit(bytes);
}

int set_gc_percent(int pct) noexcept
{
    return ITB_SetGCPercent(pct);
}

std::size_t hash_count() noexcept
{
    int n = ITB_HashCount();
    return n > 0 ? static_cast<std::size_t>(n) : 0;
}

std::string hash_name(std::size_t index)
{
    if (index > static_cast<std::size_t>(INT_MAX)) {
        detail::fail(static_cast<int>(Status::BadInput), "hash_name");
    }
    std::array<char, 128> buf{};
    std::size_t need = 0;
    detail::check(ITB_HashName(static_cast<int>(index), buf.data(), buf.size(),
                               &need),
                  "hash_name");
    return {buf.data()};
}

int hash_width(std::size_t index) noexcept
{
    if (index > static_cast<std::size_t>(INT_MAX)) {
        return 0;
    }
    int w = ITB_HashWidth(static_cast<int>(index));
    return w > 0 ? w : 0;
}

} // namespace itb
