/* Error-mapping surface: opaque-string relay, thrown itb::Error
 * status + diagnostic, close() semantics, duplicate profile
 * registration (with an 8-entry `innerHashes` constellation). */

#include <algorithm>

#include "test_util.hpp"

/* Runs fn expecting an itb::Error; stores its status in *got. */
template <typename Fn>
static bool throws_status(Fn &&fn, itb::Status *got)
{
    try {
        fn();
    } catch (const itb::Error &e) {
        *got = e.status();
        return true;
    }
    return false;
}

static int run()
{
    /* Unknown profile → BadInput + non-empty diagnostic. */
    itb::Status st = itb::Status::Ok;
    TEST_ASSERT(throws_status([] { (void)itb::Pipeline::init("no-such-profile"); },
                              &st),
                "unknown profile must throw");
    TEST_ASSERT(st == itb::Status::BadInput, "unknown profile: got %d",
                static_cast<int>(st));
    TEST_ASSERT(!itb::last_error().empty(), "diagnostic must be non-empty");

    /* Unknown opts key (typoed lowercase s) → BadInput. */
    itb::Opts bad;
    bad.set("chunksize", "4096");
    TEST_ASSERT(throws_status(
                    [&] { (void)itb::Pipeline::init("singlemsg-triple-mac-v1", bad); },
                    &st),
                "unknown opts key must throw");
    TEST_ASSERT(st == itb::Status::BadInput, "unknown opts key: got %d",
                static_cast<int>(st));

    /* An unknown inner-hash name is relayed to Go and rejected there —
     * the binding performs no name validation of its own. */
    itb::Opts hash;
    hash.set("innerHash", "no-such-hash");
    TEST_ASSERT(throws_status(
                    [&] { (void)itb::Pipeline::init("singlemsg-triple-mac-v1", hash); },
                    &st),
                "unknown hash must be rejected");

    /* A half-supplied master-override pair is rejected binding-side. */
    itb::Pipeline probe = itb::Pipeline::init("singlemsg-triple-mac-v1");
    const std::vector<std::uint8_t> perm(32, 0x33);
    TEST_ASSERT(throws_status(
                    [&] {
                        (void)itb::Pipeline::open("singlemsg-triple-mac-v1",
                                                  probe.blob(), {},
                                                  itb::as_bytes(perm), {});
                    },
                    &st),
                "half-supplied masters must throw");
    TEST_ASSERT(st == itb::Status::BadInput, "half-supplied masters: got %d",
                static_cast<int>(st));

    /* close() zeroes key material; cipher calls then throw
     * TripleClosed, and close() stays idempotent. */
    probe.close();
    probe.close();
    TEST_ASSERT(throws_status(
                    [&] { (void)probe.encrypt_message(itb::as_bytes("x")); },
                    &st),
                "cipher call after close must throw");
    TEST_ASSERT(st == itb::Status::TripleClosed, "after close: got %d",
                static_cast<int>(st));

    /* RegisterProfile with an 8-entry width-256 innerHashes
     * constellation, layers off. */
    itb::Opts reg;
    reg.set("mode", "singlemsg-nomac")
        .set("width", "256")
        .set("innerHashes",
             "blake3,blake2s,areion256,blake2b256,"
             "chacha20,blake3,blake2s,areion256")
        .set("keyBits", "1024")
        .set("parallaxOn", "false")
        .set("wrapperOn", "false");
    itb::register_profile("cpp-binding-test-mixed", reg);

    /* The registered profile round-trips. */
    itb::Pipeline sender = itb::Pipeline::init("cpp-binding-test-mixed");
    itb::Pipeline receiver =
        itb::Pipeline::open("cpp-binding-test-mixed", sender.blob());
    const std::string_view plain = "custom profile";
    std::vector<std::uint8_t> wire =
        sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back =
        receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == plain.size() &&
                    std::string_view(reinterpret_cast<const char *>(back.data()),
                                     back.size()) == plain,
                "payload mismatch");

    /* Duplicate name is a distinct status. */
    TEST_ASSERT(throws_status(
                    [&] { itb::register_profile("cpp-binding-test-mixed", reg); },
                    &st),
                "duplicate profile must throw");
    TEST_ASSERT(st == itb::Status::ProfileExists, "duplicate profile: got %d",
                static_cast<int>(st));
    return 0;
}

TEST_MAIN(run)
