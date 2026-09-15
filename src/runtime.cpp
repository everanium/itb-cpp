/*
 * runtime.cpp — Go runtime knobs and the library version.
 */

#include <array>

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

} // namespace itb
