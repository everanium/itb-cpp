/*
 * Size and duration parsing, the monotonic clock, and the human
 * renderings of sizes, rates and durations. Every rendering here is
 * part of the output contract shared with the Go harness and the
 * other bindings' loop utilities, so the formats are fixed to the
 * character, not to taste.
 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include "loop.hpp"

namespace loop {

namespace {

/* Upper-cases a trimmed copy of s; false when the value is empty or
 * longer than any size string can legitimately be. */
bool trimmed_upper(std::string_view s, std::string &out)
{
    std::size_t begin = 0;
    std::size_t end = s.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(s[begin])) != 0) {
        begin++;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        end--;
    }
    if (end == begin || end - begin >= 64) {
        return false;
    }
    out.assign(s.substr(begin, end - begin));
    for (char &c : out) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return true;
}

/* Appends the fractional part of a nanosecond remainder (0 .. 1e9)
 * as ".ddd" with trailing zeros removed; appends nothing for zero. */
void append_fraction(std::string &out, std::int64_t frac_ns)
{
    if (frac_ns == 0) {
        return;
    }
    std::string digits = fmt("%09lld", static_cast<long long>(frac_ns));
    while (!digits.empty() && digits.back() == '0') {
        digits.pop_back();
    }
    out.push_back('.');
    out += digits;
}

} // namespace

/* Parses a human byte-size string ("16MB", "1MiB", "512K",
 * "1073741824") into a byte count. Every suffix is a binary multiple:
 * K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
 * bytes; matching is case-insensitive and surrounding whitespace is
 * trimmed. Returns false on a malformed or negative value. */
bool parse_size(std::string_view s, std::int64_t &out)
{
    std::string upper;
    if (!trimmed_upper(s, upper)) {
        return false;
    }
    struct Suffix {
        const char *text;
        std::int64_t mult;
    };
    static constexpr Suffix table[] = {
        { "KIB", std::int64_t{1} << 10 }, { "KB", std::int64_t{1} << 10 },
        { "K", std::int64_t{1} << 10 },
        { "MIB", std::int64_t{1} << 20 }, { "MB", std::int64_t{1} << 20 },
        { "M", std::int64_t{1} << 20 },
        { "GIB", std::int64_t{1} << 30 }, { "GB", std::int64_t{1} << 30 },
        { "G", std::int64_t{1} << 30 },
        { "B", 1 },
    };
    std::int64_t mult = 1;
    std::size_t digits = upper.size();
    for (const Suffix &suf : table) {
        const std::size_t sl = std::strlen(suf.text);
        if (upper.size() >= sl && upper.compare(upper.size() - sl, sl, suf.text) == 0) {
            mult = suf.mult;
            digits = upper.size() - sl;
            break;
        }
    }
    while (digits > 0 && std::isspace(static_cast<unsigned char>(upper[digits - 1])) != 0) {
        digits--;
    }
    if (digits == 0) {
        return false;
    }
    for (std::size_t i = 0; i < digits; i++) {
        if (std::isdigit(static_cast<unsigned char>(upper[i])) == 0) {
            return false;
        }
    }
    upper.resize(digits);
    errno = 0;
    const long long n = std::strtoll(upper.c_str(), nullptr, 10);
    if (errno != 0 || n < 0 || (mult > 1 && n > INT64_MAX / mult)) {
        return false;
    }
    out = static_cast<std::int64_t>(n) * mult;
    return true;
}

/* Parses the Go duration grammar — a sequence of decimal numbers each
 * followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
 * "1h30m", "1.5s" — into nanoseconds. Returns false on a malformed
 * string. */
bool parse_duration(std::string_view s, std::int64_t &out_ns)
{
    struct Unit {
        const char *text;
        double ns;
    };
    static constexpr Unit units[] = {
        { "ns", 1.0 }, { "us", 1e3 }, { "ms", 1e6 },
        { "s", 1e9 }, { "m", 60e9 }, { "h", 3600e9 },
    };
    const std::string text(s);
    if (text.empty()) {
        return false;
    }
    const char *p = text.c_str();
    double total = 0.0;
    while (*p != '\0') {
        if (std::isdigit(static_cast<unsigned char>(*p)) == 0 && *p != '.') {
            return false;
        }
        char *end = nullptr;
        const double v = std::strtod(p, &end);
        if (end == p || v < 0.0) {
            return false;
        }
        p = end;
        double mult = 0.0;
        for (const Unit &u : units) {
            const std::size_t ul = std::strlen(u.text);
            if (std::strncmp(p, u.text, ul) == 0
                && std::isalpha(static_cast<unsigned char>(p[ul])) == 0) {
                mult = u.ns;
                p += ul;
                break;
            }
        }
        if (mult == 0.0) {
            return false;
        }
        total += v * mult;
    }
    if (total > 9.2e18) {
        return false;
    }
    out_ns = static_cast<std::int64_t>(total);
    return true;
}

/* Monotonic wall clock in nanoseconds. */
std::int64_t now_ns()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::int64_t>(ts.tv_sec) * 1000000000LL
           + static_cast<std::int64_t>(ts.tv_nsec);
}

/* Renders a byte count with a binary-unit suffix: "1.0GiB",
 * "16.0MiB", "4.0KiB", "512B". */
std::string human_bytes(std::int64_t n)
{
    if (n >= (std::int64_t{1} << 30)) {
        return fmt("%.1fGiB", static_cast<double>(n) / static_cast<double>(std::int64_t{1} << 30));
    }
    if (n >= (std::int64_t{1} << 20)) {
        return fmt("%.1fMiB", static_cast<double>(n) / static_cast<double>(std::int64_t{1} << 20));
    }
    if (n >= (std::int64_t{1} << 10)) {
        return fmt("%.1fKiB", static_cast<double>(n) / static_cast<double>(std::int64_t{1} << 10));
    }
    return fmt("%lldB", static_cast<long long>(n));
}

/* Renders a possibly-negative byte delta with an explicit sign. */
std::string human_bytes_signed(std::int64_t n)
{
    return n < 0 ? "-" + human_bytes(-n) : "+" + human_bytes(n);
}

/* Binary MiB per second over a nanosecond window; 0 when the window
 * is unmeasured. */
double mb_per_sec(std::int64_t bytes, std::int64_t ns)
{
    if (ns <= 0) {
        return 0.0;
    }
    return static_cast<double>(bytes) / static_cast<double>(1 << 20)
           / (static_cast<double>(ns) / 1e9);
}

/* Renders a throughput as "123.4MB/s" (binary MiB per second) or
 * "n/a" for an unmeasured window. */
std::string human_rate(std::int64_t bytes, std::int64_t ns)
{
    if (ns <= 0) {
        return "n/a";
    }
    return fmt("%.1fMB/s", mb_per_sec(bytes, ns));
}

/* Renders a duration the way Go's time.Duration prints: below one
 * second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
 * where the hour part appears when non-zero, the minute part when
 * the hour part appears or the minutes are non-zero, and the seconds
 * carry their fraction with trailing zeros removed ("5s", "5.003s",
 * "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first. */
std::string human_duration(std::int64_t ns)
{
    if (ns < 0) {
        ns = -ns;
    }
    if (ns == 0) {
        return "0s";
    }
    std::string out;
    if (ns < 1000000000LL) {
        out = fmt("%lld", static_cast<long long>(ns / 1000000LL));
        append_fraction(out, (ns % 1000000LL) * 1000LL); /* scale to 9 digits */
        out += "ms";
        return out;
    }
    const std::int64_t hours = ns / 3600000000000LL;
    std::int64_t rem = ns % 3600000000000LL;
    const std::int64_t minutes = rem / 60000000000LL;
    rem %= 60000000000LL;
    const std::int64_t seconds = rem / 1000000000LL;
    const std::int64_t frac = rem % 1000000000LL;
    if (hours > 0) {
        out += fmt("%lldh", static_cast<long long>(hours));
    }
    if (hours > 0 || minutes > 0) {
        out += fmt("%lldm", static_cast<long long>(minutes));
    }
    out += fmt("%lld", static_cast<long long>(seconds));
    append_fraction(out, frac);
    out += "s";
    return out;
}

} // namespace loop
