/* Error-mapping surface: opaque-string relay, thrown itb::Error
 * status + diagnostic, unknown profile, close() semantics, duplicate
 * profile registration (with an 8-entry `hashes` constellation). */

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
    /* Unknown profile → UnknownProfile + non-empty diagnostic, on init
     * and on lookup alike. */
    itb::Status st = itb::Status::Ok;
    TEST_ASSERT(throws_status([] { (void)itb::Pipeline::init("no-such-profile"); },
                              &st),
                "unknown profile must throw");
    TEST_ASSERT(st == itb::Status::UnknownProfile, "unknown profile: got %d",
                static_cast<int>(st));
    TEST_ASSERT(!itb::last_error().empty(), "diagnostic must be non-empty");
    TEST_ASSERT(throws_status([] { (void)itb::lookup("no-such-profile"); }, &st),
                "lookup of an unknown profile must throw");
    TEST_ASSERT(st == itb::Status::UnknownProfile, "lookup unknown: got %d",
                static_cast<int>(st));

    /* A negative maxWorkers opts value is clamped, not rejected. */
    {
        itb::Opts neg;
        neg.set("maxWorkers", "-1");
        (void)itb::Pipeline::init("singlemsg-triple-mac-v1", neg);
    }

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

    /* A half-supplied master-override pair is rejected by libitb. */
    itb::Pipeline probe = itb::Pipeline::init("singlemsg-triple-mac-v1");
    const std::vector<std::uint8_t> probe_blob = probe.save();
    const std::vector<std::uint8_t> perm(32, 0x33);
    TEST_ASSERT(throws_status(
                    [&] {
                        (void)itb::Pipeline::load(itb::as_bytes(probe_blob),
                                                  itb::as_bytes(perm), {});
                    },
                    &st),
                "half-supplied masters must throw");
    TEST_ASSERT(st == itb::Status::BadInput, "half-supplied masters: got %d",
                static_cast<int>(st));

    /* close() zeroes key material; cipher, save, and max_workers calls
     * then throw TripleClosed, and close() stays idempotent. */
    probe.close();
    probe.close();
    TEST_ASSERT(throws_status(
                    [&] { (void)probe.encrypt_message(itb::as_bytes("x")); },
                    &st),
                "cipher call after close must throw");
    TEST_ASSERT(st == itb::Status::TripleClosed, "after close: got %d",
                static_cast<int>(st));
    TEST_ASSERT(throws_status([&] { (void)probe.save(); }, &st),
                "save after close must throw");
    TEST_ASSERT(st == itb::Status::TripleClosed, "save after close: got %d",
                static_cast<int>(st));
    TEST_ASSERT(throws_status([&] { probe.max_workers(2); }, &st),
                "max_workers after close must throw");
    TEST_ASSERT(st == itb::Status::TripleClosed, "max_workers after close: got %d",
                static_cast<int>(st));

    /* register_profile with an 8-entry width-256 hashes constellation,
     * layers off. The record is a profile JSON object. */
    const std::string_view reg =
        "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
        "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
        "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
        "\"keybits\":1024,\"wrapper\":false,\"parallax\":false}";
    itb::register_profile("cpp-binding-test-mixed", reg);

    /* The registered record reads back with its name filled in. */
    const std::string looked = itb::lookup("cpp-binding-test-mixed");
    TEST_ASSERT(looked.find("\"name\":\"cpp-binding-test-mixed\"") != std::string::npos,
                "lookup must carry the name: %s", looked.c_str());
    TEST_ASSERT(looked.find("\"hashes\":[\"blake3\",\"blake2s\"") != std::string::npos,
                "lookup must carry the hashes: %s", looked.c_str());

    /* A non-empty name inside the record must equal the argument. */
    TEST_ASSERT(throws_status(
                    [&] {
                        itb::register_profile(
                            "cpp-binding-test-mismatch",
                            "{\"name\":\"other\",\"mode\":\"singlemsg-nomac\","
                            "\"width\":512,\"hash\":\"areion512\",\"keybits\":1024,"
                            "\"wrapper\":false,\"parallax\":false}");
                    },
                    &st),
                "name mismatch must throw");
    TEST_ASSERT(st == itb::Status::BadInput, "name mismatch: got %d",
                static_cast<int>(st));

    /* The registered profile round-trips. */
    itb::Pipeline sender = itb::Pipeline::init("cpp-binding-test-mixed");
    itb::Pipeline receiver =
        itb::Pipeline::load(itb::as_bytes(sender.save()));
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
