/*
 * Go runtime knobs, the library version and the auto DRBG tier.
 */

#include <array>
#include <string>

#include "internal.hpp"

namespace itb {

std::string version()
{
    std::array<char, 64> buf{};
    std::size_t need = 0;
    detail::check(ITB_Version(buf.data(), buf.size(), &need), "version");
    return {buf.data()};
}

std::string drbg_auto_tier()
{
    std::array<char, 64> buf{};
    std::size_t need = 0;
    detail::check(ITB_DRBGAutoTier(buf.data(), buf.size(), &need), "drbg_auto_tier");
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

int set_gomaxprocs(int n) noexcept
{
    return ITB_SetGOMAXPROCS(n);
}

void write_heap_profile(std::string_view path)
{
    const std::string p(path);
    detail::check(ITB_WriteHeapProfile(detail::ffi_str(p)), "write_heap_profile");
}

std::size_t pool_stats_len() noexcept
{
    const int n = ITB_PoolStatsLen();
    return n > 0 ? static_cast<std::size_t>(n) : 0;
}

std::size_t pool_stats(std::span<std::int64_t> dst)
{
    std::size_t written = 0;
    detail::check(ITB_PoolStats(dst.data(), dst.size(), &written), "pool_stats");
    return written;
}

} // namespace itb
