/* init → rekey → load receiver with the rotated blob → round trip. */

#include <algorithm>

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");

    const std::vector<std::uint8_t> before = sender.save();

    const std::vector<std::uint8_t> perm(32, 0x11);
    const std::vector<std::uint8_t> wrap(32, 0x22);
    const std::vector<std::uint8_t> rotated =
        sender.rekey(itb::as_bytes(perm), itb::as_bytes(wrap));
    TEST_ASSERT(rotated != before, "rekey must refresh the blob");
    TEST_ASSERT(sender.save() == rotated, "save must report the rotated blob");

    itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(rotated));

    const std::string_view plain = "post-rekey payload";
    std::vector<std::uint8_t> wire =
        sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back =
        receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == plain.size() &&
                    std::string_view(reinterpret_cast<const char *>(back.data()),
                                     back.size()) == plain,
                "payload mismatch");
    return 0;
}

TEST_MAIN(run)
