/*
 * test_util.hpp — minimal assertion + payload helpers shared by the
 * binding's integration tests. No framework dependency: every test is
 * a standalone binary whose main() returns non-zero on failure.
 */

#ifndef ITB_TEST_UTIL_HPP
#define ITB_TEST_UTIL_HPP

#include <cstdio>
#include <cstdint>
#include <exception>
#include <vector>

#include "itb.hpp"

/* Prints file:line + the formatted message and fails the enclosing
 * int-returning function. */
#define TEST_ASSERT(cond, ...)                                        \
    do {                                                              \
        if (!(cond)) {                                                \
            std::fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            std::fprintf(stderr, __VA_ARGS__);                        \
            std::fprintf(stderr, "\n");                               \
            return 1;                                                 \
        }                                                             \
    } while (0)

/* Standard main: expected itb::Error throws are caught inside the
 * test body; anything escaping to here is a failure. */
#define TEST_MAIN(fn)                                                 \
    int main()                                                        \
    {                                                                 \
        try {                                                         \
            return fn();                                              \
        } catch (const std::exception &e) {                           \
            std::fprintf(stderr, "FAIL: unexpected exception: %s\n",  \
                         e.what());                                   \
            return 1;                                                 \
        }                                                             \
    }

/* Deterministic non-trivial payload (xorshift fill). */
inline std::vector<std::uint8_t> test_payload(std::size_t n, std::uint64_t seed)
{
    std::vector<std::uint8_t> buf(n);
    std::uint64_t x = seed | 1u;
    for (std::size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf[i] = static_cast<std::uint8_t>(x);
    }
    return buf;
}

#endif /* ITB_TEST_UTIL_HPP */
