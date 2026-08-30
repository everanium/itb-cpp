/* Destroying an encrypt session mid-flight releases resources cleanly
 * and leaves the Pipeline usable. The process exiting without hang or
 * crash (and valgrind / ASan reporting no leak) is the assertion. */

#include "test_util.hpp"

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("streaming-aead-triple-mac-v1");

    const std::vector<std::uint8_t> chunk = test_payload(100000, 0xA5A5A5A5u);
    {
        itb::EncryptStream session = sender.encrypt_stream_begin();
        session.write(itb::as_bytes(chunk));
        /* Scope exit without end() — the destructor cancels the
         * session. */
    }

    /* The Pipeline stays usable after the cancelled session. */
    itb::Pipeline receiver =
        itb::Pipeline::open("streaming-aead-triple-mac-v1", sender.blob());

    const std::string_view plain = "after cancel";
    std::vector<std::uint8_t> wire =
        sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back =
        receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == plain.size() &&
                    std::string_view(reinterpret_cast<const char *>(back.data()),
                                     back.size()) == plain,
                "payload mismatch");

    /* Explicit close() is idempotent alongside the destructor. */
    itb::EncryptStream session = sender.encrypt_stream_begin();
    session.close();
    session.close();
    return 0;
}

TEST_MAIN(run)
