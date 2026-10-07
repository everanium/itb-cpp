/*
 * Plaintext content: the payload modes, the seeded per-worker
 * generator, and the buffer fill from the operating-system CSPRNG.
 */

#include <cstring>
#include <string_view>

#include <sys/random.h>

#include "loop.hpp"

namespace loop {

namespace {

/* Payload mode selector values for the --payload-mode flag.
 *
 *   - fixed: one CSPRNG-generated buffer per worker, held unchanged
 *     for the whole run (the default).
 *   - rotating: the buffer is regenerated before every iteration, so
 *     no two encrypt calls see the same plaintext.
 *   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
 *     all 0xFF) probing minimum-entropy plaintext handling.
 *   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
 *     structured text. */
constexpr const char *kPayloadNames[] = {
    "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
};

std::uint64_t splitmix64(std::uint64_t &state)
{
    state += 0x9E3779B97F4A7C15ull;
    std::uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

} // namespace

const char *payload_mode_name(PayloadMode mode)
{
    return kPayloadNames[static_cast<std::size_t>(mode)];
}

bool parse_payload_mode(std::string_view s, PayloadMode &out)
{
    for (std::size_t i = 0; i < std::size(kPayloadNames); i++) {
        if (s == kPayloadNames[i]) {
            out = static_cast<PayloadMode>(i);
            return true;
        }
    }
    return false;
}

/* Seeded plaintext. The seed makes plaintext content reproducible so
 * a failing iteration can be replayed with the same bytes; it governs
 * nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
 * so a seeded run is a reproduction aid and never a security test.
 * Each worker's stream is domain-separated by its id so seeded
 * workers still hold pairwise-distinct buffers under the fixed and
 * rotating modes. The generator is splitmix64: a few lines in any
 * language, which is why it is the one every binding uses. */
std::uint64_t seed_worker(std::uint64_t seed, int worker_id)
{
    return seed + static_cast<std::uint64_t>(worker_id) + 1u;
}

/* Fills buf from the operating-system CSPRNG. C++-specific: getrandom
 * returns at most ~33 MiB per call and may return short on a signal,
 * so the fill loops until every byte is in place. The syscall wrapper
 * is called directly rather than through <random>, which offers no
 * CSPRNG guarantee. */
bool fill_random(std::span<std::uint8_t> buf)
{
    std::size_t off = 0;
    while (off < buf.size()) {
        const ssize_t r = getrandom(buf.data() + off, buf.size() - off, 0);
        if (r <= 0) {
            return false;
        }
        off += static_cast<std::size_t>(r);
    }
    return true;
}

/* Writes one plaintext buffer according to the payload mode. The
 * fixed and rotating modes draw from the seeded generator when the
 * run is seeded and from the OS CSPRNG otherwise; the pattern modes
 * are deterministic regardless of the seed. Returns false when the
 * CSPRNG fails. */
bool fill_payload(PayloadMode mode, bool seeded, std::uint64_t &rng,
                  std::span<std::uint8_t> buf)
{
    switch (mode) {
    case PayloadMode::Fixed:
    case PayloadMode::Rotating:
        if (!seeded) {
            return fill_random(buf);
        }
        for (std::size_t i = 0; i < buf.size(); i += 8) {
            const std::uint64_t v = splitmix64(rng);
            const std::size_t take = buf.size() - i < 8 ? buf.size() - i : 8;
            std::memcpy(buf.data() + i, &v, take);
        }
        return true;
    case PayloadMode::PatternZero:
        std::memset(buf.data(), 0x00, buf.size());
        return true;
    case PayloadMode::PatternFF:
        std::memset(buf.data(), 0xFF, buf.size());
        return true;
    case PayloadMode::PatternAscii:
        for (std::size_t i = 0; i < buf.size(); i++) {
            buf[i] = static_cast<std::uint8_t>('A' + (i % 26));
        }
        return true;
    }
    return false;
}

} // namespace loop
