/* Explicit write / end / read round trip with pathological batch
 * sizes (17-byte feed, 23-byte drain) across multiple chunks. */

#include <algorithm>

#include "test_util.hpp"

/* Feeds src in 17-byte writes, ends, drains in 23-byte reads. */
template <typename Session>
static std::vector<std::uint8_t> feed_drain(Session session,
                                            std::span<const std::byte> src)
{
    for (std::size_t off = 0; off < src.size(); off += 17) {
        session.write(src.subspan(off, std::min<std::size_t>(17, src.size() - off)));
    }
    session.end();

    std::vector<std::uint8_t> out;
    std::byte piece[23];
    for (;;) {
        const itb::StreamRead r = session.read(piece);
        const auto *first = reinterpret_cast<const std::uint8_t *>(piece);
        out.insert(out.end(), first, first + r.n);
        if (r.finished) {
            break;
        }
    }
    return out;
}

static int run()
{
    /* Small chunk size so the 64 KiB payload spans many chunks. */
    itb::Opts opts;
    opts.set("chunkSize", "4096");

    itb::Pipeline sender =
        itb::Pipeline::init("streaming-aead-triple-mac-v1", opts);
    itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::size_t size = 65536;
    std::vector<std::uint8_t> plain(size);
    for (std::size_t i = 0; i < size; i++) {
        plain[i] = static_cast<std::uint8_t>(i % 241);
    }

    std::vector<std::uint8_t> wire =
        feed_drain(sender.encrypt_stream_begin(), itb::as_bytes(plain));
    TEST_ASSERT(!wire.empty(), "wire must be non-empty");

    std::vector<std::uint8_t> back =
        feed_drain(receiver.decrypt_stream_begin(), itb::as_bytes(wire));
    TEST_ASSERT(back.size() == size, "length %zu != %zu", back.size(), size);
    TEST_ASSERT(back == plain, "payload mismatch");
    return 0;
}

TEST_MAIN(run)
