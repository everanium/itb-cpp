/* Reusable-buffer *_into entries: Single Message and whole-buffer
 * pump round trips through caller-owned scratch reused across calls,
 * parity with the vector-returning entries, and the undersized-dst
 * failure contracts. */

#include <algorithm>

#include "test_util.hpp"

/* One shared scratch pair reused verbatim across every round trip:
 * the *_into contract is that dst is grown once (via itb::out_bound)
 * and rewritten in place thereafter. */
static int message_into_round_trips(const char *profile)
{
    itb::Pipeline sender = itb::Pipeline::init(profile);
    itb::Pipeline receiver = itb::Pipeline::open(profile, sender.blob());

    static const std::size_t sizes[] = { 1, 4 * 1024, 256 * 1024 };
    const std::size_t max_size = 256 * 1024;

    std::vector<std::uint8_t> wire(itb::out_bound(max_size));
    std::vector<std::uint8_t> back(itb::out_bound(max_size));

    for (std::size_t size : sizes) {
        const std::vector<std::uint8_t> plain =
            test_payload(size, static_cast<std::uint64_t>(size) + 7);

        const std::size_t n_wire = sender.encrypt_message_into(
            itb::as_bytes(plain), itb::as_writable_bytes(wire));
        TEST_ASSERT(n_wire > 0 && n_wire <= wire.size(),
                    "%s @%zu: wire length %zu", profile, size, n_wire);

        const std::size_t n_back = receiver.decrypt_message_into(
            itb::as_bytes(std::span<const std::uint8_t>(wire.data(), n_wire)),
            itb::as_writable_bytes(back));
        TEST_ASSERT(n_back == size, "%s @%zu: length %zu", profile, size,
                    n_back);
        TEST_ASSERT(std::equal(plain.begin(), plain.end(), back.begin()),
                    "%s @%zu: mismatch", profile, size);
    }
    return 0;
}

static int pump_into_round_trips(const char *profile)
{
    itb::Pipeline sender = itb::Pipeline::init(profile);
    itb::Pipeline receiver = itb::Pipeline::open(profile, sender.blob());

    /* 3 MiB spans several internal pump slices. */
    static const std::size_t sizes[] = { 1, 4 * 1024, 3 * 1024 * 1024 };
    const std::size_t max_size = 3 * 1024 * 1024;

    std::vector<std::uint8_t> wire(itb::out_bound(max_size));
    std::vector<std::uint8_t> back(itb::out_bound(max_size));

    for (std::size_t size : sizes) {
        const std::vector<std::uint8_t> plain =
            test_payload(size, static_cast<std::uint64_t>(size) + 11);

        const std::size_t n_wire = sender.encrypt_stream_pump_into(
            itb::as_bytes(plain), itb::as_writable_bytes(wire));
        TEST_ASSERT(n_wire > 0 && n_wire <= wire.size(),
                    "%s @%zu: wire length %zu", profile, size, n_wire);

        const std::size_t n_back = receiver.decrypt_stream_pump_into(
            itb::as_bytes(std::span<const std::uint8_t>(wire.data(), n_wire)),
            itb::as_writable_bytes(back));
        TEST_ASSERT(n_back == size, "%s @%zu: length %zu", profile, size,
                    n_back);
        TEST_ASSERT(std::equal(plain.begin(), plain.end(), back.begin()),
                    "%s @%zu: mismatch", profile, size);
    }
    return 0;
}

/* Cross-parity: a wire produced by the *_into entry decrypts through
 * the vector-returning entry and vice versa. */
static int into_vector_parity(const char *profile)
{
    itb::Pipeline sender = itb::Pipeline::init(profile);
    itb::Pipeline receiver = itb::Pipeline::open(profile, sender.blob());

    const std::size_t size = 16 * 1024;
    const std::vector<std::uint8_t> plain = test_payload(size, 42);

    std::vector<std::uint8_t> wire(itb::out_bound(size));
    const std::size_t n_wire = sender.encrypt_message_into(
        itb::as_bytes(plain), itb::as_writable_bytes(wire));
    const std::vector<std::uint8_t> back = receiver.decrypt_message(
        itb::as_bytes(std::span<const std::uint8_t>(wire.data(), n_wire)));
    TEST_ASSERT(back == plain, "%s: into->vector mismatch", profile);

    const std::vector<std::uint8_t> wire2 =
        sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back2(itb::out_bound(wire2.size()));
    const std::size_t n_back2 = receiver.decrypt_message_into(
        itb::as_bytes(wire2), itb::as_writable_bytes(back2));
    TEST_ASSERT(n_back2 == size &&
                    std::equal(plain.begin(), plain.end(), back2.begin()),
                "%s: vector->into mismatch", profile);
    return 0;
}

/* Empty-input rejection contract for the message entries: the
 * triple.Pipeline layer rejects a zero-byte plaintext / wire before
 * any wire is produced or parsed, surfacing Status::BadInput. */
static int empty_message_rejected(const char *profile)
{
    itb::Pipeline sender = itb::Pipeline::init(profile);
    itb::Pipeline receiver = itb::Pipeline::open(profile, sender.blob());

    std::vector<std::uint8_t> scratch(itb::out_bound(1024));

    bool threw = false;
    try {
        (void)sender.encrypt_message_into(
            std::span<const std::byte>{}, itb::as_writable_bytes(scratch));
    } catch (const itb::Error &e) {
        threw = e.status() == itb::Status::BadInput;
    }
    TEST_ASSERT(threw, "%s: empty encrypt input not rejected", profile);

    threw = false;
    try {
        (void)receiver.decrypt_message_into(
            std::span<const std::byte>{}, itb::as_writable_bytes(scratch));
    } catch (const itb::Error &e) {
        threw = e.status() == itb::Status::BadInput;
    }
    TEST_ASSERT(threw, "%s: empty decrypt input not rejected", profile);
    return 0;
}

/* Empty-input rejection contract for the pump entries: the session
 * surfaces the same rejection on the drain after end-of-input. */
static int empty_pump_rejected(const char *profile)
{
    itb::Pipeline pipe = itb::Pipeline::init(profile);
    std::vector<std::uint8_t> scratch(itb::out_bound(1024));

    bool threw = false;
    try {
        (void)pipe.encrypt_stream_pump_into(
            std::span<const std::byte>{}, itb::as_writable_bytes(scratch));
    } catch (const itb::Error &e) {
        threw = e.status() == itb::Status::BadInput;
    }
    TEST_ASSERT(threw, "%s: empty pump input not rejected", profile);
    return 0;
}

/* Undersized-dst contract for the message entry: relays
 * Status::BufferTooSmall as itb::Error. */
static int undersized_message_dst(const char *profile)
{
    itb::Pipeline pipe = itb::Pipeline::init(profile);
    const std::vector<std::uint8_t> plain = test_payload(64 * 1024, 3);
    std::vector<std::uint8_t> tiny(16);

    bool threw = false;
    try {
        (void)pipe.encrypt_message_into(itb::as_bytes(plain),
                                        itb::as_writable_bytes(tiny));
    } catch (const itb::Error &e) {
        threw = e.status() == itb::Status::BufferTooSmall;
    }
    TEST_ASSERT(threw, "%s: undersized message dst not rejected", profile);
    return 0;
}

/* Undersized-dst contract for the pump entry: throws
 * std::invalid_argument from the drain-tail bound check. */
static int undersized_pump_dst(const char *profile)
{
    itb::Pipeline pipe = itb::Pipeline::init(profile);
    const std::vector<std::uint8_t> plain = test_payload(64 * 1024, 5);
    std::vector<std::uint8_t> tiny(16);

    bool threw = false;
    try {
        (void)pipe.encrypt_stream_pump_into(itb::as_bytes(plain),
                                            itb::as_writable_bytes(tiny));
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    TEST_ASSERT(threw, "%s: undersized pump dst not rejected", profile);
    return 0;
}

static int run()
{
    static const char *const profiles[] = {
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
    };
    for (const char *profile : profiles) {
        int rc = message_into_round_trips(profile);
        if (rc == 0) {
            rc = into_vector_parity(profile);
        }
        if (rc == 0) {
            rc = undersized_message_dst(profile);
        }
        if (rc == 0) {
            rc = empty_message_rejected(profile);
        }
        if (rc != 0) {
            return rc;
        }
    }
    static const char *const stream_profiles[] = {
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
    };
    for (const char *profile : stream_profiles) {
        int rc = pump_into_round_trips(profile);
        if (rc == 0) {
            rc = undersized_pump_dst(profile);
        }
        if (rc == 0) {
            rc = empty_pump_rejected(profile);
        }
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

TEST_MAIN(run)
