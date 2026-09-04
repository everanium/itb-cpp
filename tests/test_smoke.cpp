/* init → save → load → encrypt_message → decrypt_message round trip. */

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");
    TEST_ASSERT(!sender.save().empty(), "blob must be non-empty");

    itb::Pipeline receiver =
        itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::string_view plain = "smoke round-trip payload";

    std::vector<std::uint8_t> wire =
        sender.encrypt_message(itb::as_bytes(plain));
    TEST_ASSERT(wire.size() != plain.size() ||
                    std::string_view(reinterpret_cast<const char *>(wire.data()),
                                     wire.size()) != plain,
                "wire must differ from plaintext");

    std::vector<std::uint8_t> back =
        receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == plain.size(), "length %zu != %zu",
                back.size(), plain.size());
    TEST_ASSERT(std::string_view(reinterpret_cast<const char *>(back.data()),
                                 back.size()) == plain,
                "payload mismatch");
    return 0;
}

TEST_MAIN(run)
