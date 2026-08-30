/*
 * opts.cpp — URL-query builder for the opts pass-through string.
 *
 * The builder performs no validation — every key and value is
 * percent-encoded into a query string and passed through to Go
 * verbatim; libitb rejects unknown keys or bad values with a
 * diagnostic carried by the thrown itb::Error. Primitive / MAC /
 * cipher / profile names are opaque strings.
 */

#include "internal.hpp"

namespace itb {

namespace {

/* Unreserved URL characters plus ',' (comma-separated list values
 * cross unescaped, matching the fleet convention). */
bool url_safe(unsigned char b) noexcept
{
    return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
           (b >= '0' && b <= '9') || b == '-' || b == '.' ||
           b == '_' || b == '~' || b == ',';
}

void encode_into(std::string &dst, std::string_view s)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    for (char c : s) {
        auto b = static_cast<unsigned char>(c);
        if (url_safe(b)) {
            dst.push_back(c);
        } else {
            dst.push_back('%');
            dst.push_back(hex[b >> 4]);
            dst.push_back(hex[b & 0x0F]);
        }
    }
}

} // namespace

Opts &Opts::set(std::string_view key, std::string_view value)
{
    if (!query_.empty()) {
        query_.push_back('&');
    }
    encode_into(query_, key);
    query_.push_back('=');
    encode_into(query_, value);
    return *this;
}

} // namespace itb
