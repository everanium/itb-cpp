/* A decrypt session fed a tampered wire fails with a sticky
 * Status::MacFailure.
 *
 * A single bit flip can land in the container's CSPRNG residue —
 * over-sized container area that carries no payload — where the
 * decrypt legitimately completes clean. The test therefore probes
 * successive flip positions, each against a fresh session on a fresh
 * copy of the wire, until one lands in authenticated content; the
 * observed failure must be MAC failure and must be sticky. The
 * probe is black-box — no wire-layout knowledge is used. */

#include "test_util.hpp"

/* Feeds one tampered wire copy through a fresh decrypt session.
 * Returns 0 when the session finishes clean (flip landed in
 * unauthenticated residue), 1 when it failed with the expected
 * sticky MAC failure, and negative on an assertion violation
 * (message already printed). */
static int probe_once(const itb::Pipeline &receiver,
                      const std::vector<std::uint8_t> &wire,
                      std::size_t flip_pos)
{
    std::vector<std::uint8_t> tampered = wire;
    tampered[flip_pos] ^= 0x01;

    itb::DecryptStream session = receiver.decrypt_stream_begin();

    /* The failure may surface on write or end (chain already failed)
     * — either way a read must eventually report it. */
    try {
        session.write(itb::as_bytes(tampered));
        session.end();
    } catch (const itb::Error &) {
    }

    std::byte buf[4096];
    bool clean = false;
    itb::Status first = itb::Status::Ok;
    try {
        for (;;) {
            const itb::StreamRead r = session.read(buf);
            if (r.finished) {
                clean = true;
                break;
            }
        }
    } catch (const itb::Error &e) {
        first = e.status();
    }

    if (clean) {
        return 0; /* flip landed in residue — try the next position */
    }
    if (first != itb::Status::MacFailure) {
        std::fprintf(stderr, "FAIL: expected MAC failure at pos %zu, got %d (%s)\n",
                     flip_pos, static_cast<int>(first), itb::status_str(first));
        return -1;
    }
    /* Sticky: a subsequent read reports the same status. */
    try {
        (void)session.read(buf);
        std::fprintf(stderr, "FAIL: sticky status: second read succeeded\n");
        return -1;
    } catch (const itb::Error &e) {
        if (e.status() != first) {
            std::fprintf(stderr, "FAIL: sticky status: got %d, want %d\n",
                         static_cast<int>(e.status()), static_cast<int>(first));
            return -1;
        }
    }
    return 1;
}

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("streaming-aead-triple-mac-v1");
    itb::Pipeline receiver =
        itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::size_t size = 65536;
    std::vector<std::uint8_t> plain(size);
    for (std::size_t i = 0; i < size; i++) {
        plain[i] = static_cast<std::uint8_t>(i % 227);
    }

    std::vector<std::uint8_t> wire =
        sender.encrypt_stream_pump(itb::as_bytes(plain));
    TEST_ASSERT(!wire.empty(), "wire must be non-empty");

    bool seen_failure = false;
    for (std::size_t attempt = 0; attempt < 32 && !seen_failure; attempt++) {
        const std::size_t flip_pos =
            (wire.size() * 3 / 4 + attempt * 1031) % wire.size();
        int rc = probe_once(receiver, wire, flip_pos);
        if (rc < 0) {
            return 1;
        }
        seen_failure = rc != 0;
    }
    TEST_ASSERT(seen_failure,
                "no flip position produced an authentication failure");
    return 0;
}

TEST_MAIN(run)
