/* Single Message round trip across every shipped cipher-bearing
 * profile at small (4 KiB) and medium (256 KiB) payloads. The
 * blob-only profile has no cipher surface and is exercised in
 * test_errors.cpp instead. */

#include "test_util.hpp"

static int round_trip(const char *profile, std::size_t size)
{
    itb::Pipeline sender = itb::Pipeline::init(profile);
    itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(sender.save()));

    const std::vector<std::uint8_t> plain =
        test_payload(size, static_cast<std::uint64_t>(size));

    std::vector<std::uint8_t> wire =
        sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back =
        receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == size, "%s @%zu: length %zu", profile, size,
                back.size());
    TEST_ASSERT(back == plain, "%s @%zu: mismatch", profile, size);
    return 0;
}

static int run()
{
    static const char *const profiles[] = {
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    };
    static const std::size_t sizes[] = { 4 * 1024, 256 * 1024 };
    for (const char *profile : profiles) {
        for (std::size_t size : sizes) {
            int rc = round_trip(profile, size);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}

TEST_MAIN(run)
