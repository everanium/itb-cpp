/* Persistence surface: save / save_f / load / load_f round trips,
 * inspect, lookup / profiles, max_workers. */

#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>

#include "test_util.hpp"

static int round_trip(const itb::Pipeline &sender, const itb::Pipeline &receiver,
                      const char *what)
{
    const std::string_view plain = "persist payload";
    std::vector<std::uint8_t> wire = sender.encrypt_message(itb::as_bytes(plain));
    std::vector<std::uint8_t> back = receiver.decrypt_message(itb::as_bytes(wire));
    TEST_ASSERT(back.size() == plain.size() &&
                    std::string_view(reinterpret_cast<const char *>(back.data()),
                                     back.size()) == plain,
                "%s: payload mismatch", what);
    return 0;
}

static int run()
{
    itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");

    /* save → load, save stable, load retains the bytes. */
    const std::vector<std::uint8_t> blob = sender.save();
    TEST_ASSERT(sender.save() == blob, "save must be stable");
    {
        itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(blob));
        if (round_trip(sender, receiver, "in-memory") != 0) {
            return 1;
        }
        TEST_ASSERT(receiver.save() == blob, "load must retain the blob bytes");
    }

    /* load with master overrides == sender rekey. */
    const std::vector<std::uint8_t> perm(32, 0x31);
    const std::vector<std::uint8_t> wrap(32, 0x32);
    {
        itb::Pipeline receiver =
            itb::Pipeline::load(itb::as_bytes(blob), itb::as_bytes(perm), itb::as_bytes(wrap));
        TEST_ASSERT(receiver.save() != blob, "master overrides must rotate the blob");
        (void)sender.rekey(itb::as_bytes(perm), itb::as_bytes(wrap));
        if (round_trip(sender, receiver, "overrides") != 0) {
            return 1;
        }
    }

    /* inspect == lookup for a shipped profile; garbage throws BadInput. */
    const std::string inspected = itb::inspect(itb::as_bytes(blob));
    const std::string looked = itb::lookup("singlemsg-triple-mac-v1");
    TEST_ASSERT(inspected == looked, "inspect / lookup mismatch:\n  %s\n  %s",
                inspected.c_str(), looked.c_str());
    TEST_ASSERT(inspected.find("\"name\":\"singlemsg-triple-mac-v1\"") != std::string::npos,
                "inspect must carry the name");
    TEST_ASSERT(inspected.find("\"mode\":\"singlemsg-mac\"") != std::string::npos,
                "inspect must carry the mode");
    try {
        (void)itb::inspect(itb::as_bytes("not a blob"));
        TEST_ASSERT(false, "inspect garbage must throw");
    } catch (const itb::Error &e) {
        TEST_ASSERT(e.status() == itb::Status::BadInput, "inspect garbage: got %d",
                    static_cast<int>(e.status()));
    }

    /* profiles lists the shipped catalogue as a JSON string array. */
    const std::string names = itb::profiles();
    TEST_ASSERT(!names.empty() && names.front() == '[', "profiles must be a JSON array: %s",
                names.c_str());
    TEST_ASSERT(names.find("\"singlemsg-triple-mac-v1\"") != std::string::npos,
                "profiles must list the shipped profile: %s", names.c_str());

    /* save_f → load_f on a temp file (mode 0600), missing file. */
    const std::string path = "/tmp/itb-cpp-persist-" + std::to_string(getpid()) + ".blob";
    sender.save_f(path);
    struct stat sb{};
    TEST_ASSERT(stat(path.c_str(), &sb) == 0, "saved file must exist");
    TEST_ASSERT((sb.st_mode & 0777) == 0600, "mode %o != 0600",
                static_cast<unsigned>(sb.st_mode & 0777));
    TEST_ASSERT(static_cast<std::size_t>(sb.st_size) == sender.save().size(),
                "file size mismatch");
    {
        itb::Pipeline receiver = itb::Pipeline::load_f(path);
        if (round_trip(sender, receiver, "on-disk") != 0) {
            return 1;
        }
    }
    (void)unlink(path.c_str());
    try {
        (void)itb::Pipeline::load_f(path);
        TEST_ASSERT(false, "load_f of a missing file must throw");
    } catch (const itb::Error &e) {
        TEST_ASSERT(e.status() == itb::Status::BadInput, "load_f missing: got %d",
                    static_cast<int>(e.status()));
    }

    /* max_workers clamps and round-trips. */
    sender.max_workers(2);
    sender.max_workers(-1);
    sender.max_workers(100000);
    {
        itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(sender.save()));
        receiver.max_workers(1);
        if (round_trip(sender, receiver, "workers") != 0) {
            return 1;
        }
    }
    return 0;
}

TEST_MAIN(run)
