/* Round trip through the whole-buffer stream pumps on a Streaming
 * AEAD profile at 1 MiB. */

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("streaming-aead-triple-mac-v1");
    itb::Pipeline receiver =
        itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::size_t size = std::size_t{1} << 20;
    const std::vector<std::uint8_t> plain = test_payload(size, 0x9E3779B9u);

    std::vector<std::uint8_t> wire =
        sender.encrypt_stream_pump(itb::as_bytes(plain));
    TEST_ASSERT(!wire.empty(), "wire must be non-empty");

    std::vector<std::uint8_t> back =
        receiver.decrypt_stream_pump(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == size, "length %zu != %zu", back.size(), size);
    TEST_ASSERT(back == plain, "payload mismatch");
    return 0;
}

TEST_MAIN(run)
