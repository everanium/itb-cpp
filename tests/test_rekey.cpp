/* init → rekey → open receiver with the rotated blob → round trip. */

#include <algorithm>

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");

    const std::span<const std::byte> before_view = sender.blob();
    const std::vector<std::byte> before(before_view.begin(), before_view.end());

    const std::vector<std::uint8_t> perm(32, 0x11);
    const std::vector<std::uint8_t> wrap(32, 0x22);
    sender.rekey(itb::as_bytes(perm), itb::as_bytes(wrap));
    const std::span<const std::byte> after = sender.blob();
    TEST_ASSERT(after.size() != before.size() ||
                    !std::equal(after.begin(), after.end(), before.begin()),
                "rekey must refresh the blob");

    itb::Pipeline receiver =
        itb::Pipeline::open("singlemsg-triple-mac-v1", sender.blob());

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
