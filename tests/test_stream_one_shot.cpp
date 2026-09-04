/* Round trip through the one-shot stream entries on a Streaming AEAD
 * profile at 256 KiB, wire cross-check against the pump path, the
 * reusable-buffer *_into variants, and a tampered-wire rejection. */

#include <algorithm>

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("streaming-aead-triple-mac-v1");
    itb::Pipeline receiver =
        itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::size_t size = std::size_t{256} * 1024;
    const std::vector<std::uint8_t> plain = test_payload(size, 0xA5A5A5A5u);

    std::vector<std::uint8_t> wire =
        sender.encrypt_stream_one_shot(itb::as_bytes(plain));
    TEST_ASSERT(!wire.empty(), "wire must be non-empty");

    const std::vector<std::uint8_t> back =
        receiver.decrypt_stream_one_shot(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == size, "length %zu != %zu", back.size(), size);
    TEST_ASSERT(back == plain, "payload mismatch");

    /* The one-shot wire decodes through the pump path too. */
    const std::vector<std::uint8_t> back2 =
        receiver.decrypt_stream_pump(itb::as_bytes(wire));
    TEST_ASSERT(back2 == plain, "pump payload mismatch");

    /* Reusable-buffer *_into round trip through the same scratch. */
    std::vector<std::uint8_t> wire_into(itb::out_bound(size));
    const std::size_t n_wire = sender.encrypt_stream_one_shot_into(
        itb::as_bytes(plain), itb::as_writable_bytes(wire_into));
    TEST_ASSERT(n_wire > 0 && n_wire <= wire_into.size(),
                "into wire length %zu", n_wire);

    std::vector<std::uint8_t> back_into(itb::out_bound(size));
    const std::size_t n_back = receiver.decrypt_stream_one_shot_into(
        itb::as_bytes(std::span<const std::uint8_t>(wire_into.data(), n_wire)),
        itb::as_writable_bytes(back_into));
    TEST_ASSERT(n_back == size, "into length %zu != %zu", n_back, size);
    TEST_ASSERT(std::equal(plain.begin(), plain.end(), back_into.begin()),
                "into payload mismatch");

    /* A bit flip in authenticated wire content is rejected. A single
     * flip can land in the container's CSPRNG residue — where the
     * decrypt legitimately completes clean — so successive flip
     * positions are probed until one is rejected. The probe is
     * black-box. */
    bool seen_failure = false;
    for (std::size_t attempt = 0; attempt < 32 && !seen_failure; ++attempt) {
        const std::size_t flip_pos =
            (wire.size() * 3 / 4 + attempt * 1031) % wire.size();
        wire[flip_pos] ^= 0x01u;
        try {
            const std::vector<std::uint8_t> back_flip =
                receiver.decrypt_stream_one_shot(itb::as_bytes(wire));
            /* Flip landed in unauthenticated residue. */
            TEST_ASSERT(back_flip == plain,
                        "residue-flip decrypt must still round-trip");
        } catch (const itb::Error &) {
            seen_failure = true;
        }
        wire[flip_pos] ^= 0x01u; /* restore for the next probe */
    }
    TEST_ASSERT(seen_failure,
                "no flip position produced an authentication failure");
    return 0;
}

TEST_MAIN(run)
