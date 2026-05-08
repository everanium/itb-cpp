// test_blob_errors.cpp — Blob exception path coverage.
//
// Exercises the three Blob-specific exception classes:
//
//   - ItbBlobModeMismatchError — Single blob fed to import_triple,
//     and Triple blob fed to import_blob.
//   - ItbBlobMalformedError    — non-JSON garbage, wrong shape,
//     truncated valid blob.
//   - ItbBlobVersionTooNewError — JSON blob whose `v` field exceeds
//     any version this libitb build supports.
//
// For each path, the test confirms three orthogonal catch idioms
// succeed:
//
//   - typed-subclass catch (REQUIRE_THROWS_AS the specific class);
//   - base-class catch (REQUIRE_THROWS_AS itb::ItbError, code() check);
//   - polymorphic std::exception catch (what() string sanity).
//
// The three exception subtypes are also asserted to be distinct
// types — dynamic_cast across siblings returns nullptr while the
// matching type unwraps.
//
// Mirrors bindings/c/tests/test_blob.c::test_blob_malformed +
// test_blob_version_too_new + test_blob_mode_mismatch, adapted to
// Catch2 v3 + the C++ exception hierarchy.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(s.data());
    return std::vector<std::uint8_t>{p, p + s.size()};
}

// Build a Single-mode blob suitable for the import_triple-rejects
// scenarios.
std::vector<std::uint8_t> make_single_blob() {
    itb::Seed ns{"blake3", 1024};
    itb::Seed ds{"blake3", 1024};
    itb::Seed ss{"blake3", 1024};
    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());
    return sender.export_blob(itb::blob::None);
}

std::vector<std::uint8_t> make_triple_blob() {
    itb::Seed ns{"blake3", 1024}, d1{"blake3", 1024}, d2{"blake3", 1024};
    itb::Seed d3{"blake3", 1024}, s1{"blake3", 1024}, s2{"blake3", 1024};
    itb::Seed s3{"blake3", 1024};
    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise,  ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise,  ns.components());
    sender.set_key(itb::blob::Slot::Data1,  d1.hash_key());
    sender.set_components(itb::blob::Slot::Data1,  d1.components());
    sender.set_key(itb::blob::Slot::Data2,  d2.hash_key());
    sender.set_components(itb::blob::Slot::Data2,  d2.components());
    sender.set_key(itb::blob::Slot::Data3,  d3.hash_key());
    sender.set_components(itb::blob::Slot::Data3,  d3.components());
    sender.set_key(itb::blob::Slot::Start1, s1.hash_key());
    sender.set_components(itb::blob::Slot::Start1, s1.components());
    sender.set_key(itb::blob::Slot::Start2, s2.hash_key());
    sender.set_components(itb::blob::Slot::Start2, s2.components());
    sender.set_key(itb::blob::Slot::Start3, s3.hash_key());
    sender.set_components(itb::blob::Slot::Start3, s3.components());
    return sender.export_triple(itb::blob::None);
}

// A hand-built JSON blob with `v=99` (above any version this libitb
// build supports). The Blob512-side reader rejects with
// STATUS_BLOB_VERSION_TOO_NEW. The shape mirrors the C-binding
// fixture in bindings/c/tests/test_blob.c::test_blob_version_too_new.
constexpr std::string_view kTooNewBlob512 =
    "{\"v\":99,\"mode\":1,\"key_bits\":512,"
    "\"key_n\":\""
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000\","
    "\"key_d\":\""
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000\","
    "\"key_s\":\""
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000\","
    "\"ns\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
    "\"ds\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
    "\"ss\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
    "\"globals\":{\"nonce_bits\":128,\"barrier_fill\":1,"
    "\"bit_soup\":0,\"lock_soup\":0}}";

} // namespace

// ─── ItbBlobModeMismatchError ─────────────────────────────────────

TEST_CASE("import_triple on a Single blob raises ItbBlobModeMismatchError",
          "[blob-errors][mode-mismatch]") {
    auto blob = make_single_blob();

    SECTION("typed-subclass catch") {
        itb::Blob256 receiver{};
        REQUIRE_THROWS_AS(receiver.import_triple(blob),
                          itb::ItbBlobModeMismatchError);
    }
    SECTION("base ItbError catch") {
        itb::Blob256 receiver{};
        REQUIRE_THROWS_AS(receiver.import_triple(blob), itb::ItbError);
    }
    SECTION("std::exception catch") {
        itb::Blob256 receiver{};
        REQUIRE_THROWS_AS(receiver.import_triple(blob), std::exception);
    }
    SECTION("code + dynamic_cast unwrap") {
        itb::Blob256 receiver{};
        try {
            receiver.import_triple(blob);
            FAIL("expected ItbBlobModeMismatchError");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBlobModeMismatch);
            REQUIRE(dynamic_cast<const itb::ItbBlobModeMismatchError*>(&e)
                    != nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobMalformedError*>(&e)
                    == nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobVersionTooNewError*>(&e)
                    == nullptr);
        }
    }
}

TEST_CASE("import_blob on a Triple blob raises ItbBlobModeMismatchError",
          "[blob-errors][mode-mismatch]") {
    auto blob = make_triple_blob();

    SECTION("typed-subclass catch") {
        itb::Blob256 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(blob),
                          itb::ItbBlobModeMismatchError);
    }
    SECTION("code") {
        itb::Blob256 receiver{};
        try {
            receiver.import_blob(blob);
            FAIL("expected ItbBlobModeMismatchError");
        } catch (const itb::ItbBlobModeMismatchError& e) {
            REQUIRE(e.code() == itb::status::kBlobModeMismatch);
        }
    }
}

// ─── ItbBlobMalformedError ─────────────────────────────────────────

TEST_CASE("import_blob on non-JSON garbage raises ItbBlobMalformedError",
          "[blob-errors][malformed]") {
    auto bad = bytes_of("{not json");

    SECTION("typed-subclass catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(bad),
                          itb::ItbBlobMalformedError);
    }
    SECTION("base ItbError catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(bad), itb::ItbError);
    }
    SECTION("std::exception catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(bad), std::exception);
    }
    SECTION("code + dynamic_cast unwrap") {
        itb::Blob512 receiver{};
        try {
            receiver.import_blob(bad);
            FAIL("expected ItbBlobMalformedError");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBlobMalformed);
            REQUIRE(dynamic_cast<const itb::ItbBlobMalformedError*>(&e)
                    != nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobModeMismatchError*>(&e)
                    == nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobVersionTooNewError*>(&e)
                    == nullptr);
        }
    }
}

TEST_CASE("import_blob on truncated valid blob raises ItbBlobMalformedError",
          "[blob-errors][malformed][truncated]") {
    auto blob = make_single_blob();
    REQUIRE(blob.size() > 16);
    blob.resize(blob.size() / 2); // truncate

    itb::Blob256 receiver{};
    REQUIRE_THROWS_AS(receiver.import_blob(blob),
                      itb::ItbBlobMalformedError);
}

TEST_CASE("import_blob on shape-mismatched JSON raises ItbBlobMalformedError",
          "[blob-errors][malformed][shape]") {
    auto bad = bytes_of(R"({"v":1,"random":"object"})");

    itb::Blob256 receiver{};
    REQUIRE_THROWS_AS(receiver.import_blob(bad),
                      itb::ItbBlobMalformedError);
}

// ─── ItbBlobVersionTooNewError ─────────────────────────────────────

TEST_CASE("import_blob on a too-new-version blob raises ItbBlobVersionTooNewError",
          "[blob-errors][version-too-new]") {
    auto blob = bytes_of(kTooNewBlob512);

    SECTION("typed-subclass catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(blob),
                          itb::ItbBlobVersionTooNewError);
    }
    SECTION("base ItbError catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(blob), itb::ItbError);
    }
    SECTION("std::exception catch") {
        itb::Blob512 receiver{};
        REQUIRE_THROWS_AS(receiver.import_blob(blob), std::exception);
    }
    SECTION("code + dynamic_cast unwrap") {
        itb::Blob512 receiver{};
        try {
            receiver.import_blob(blob);
            FAIL("expected ItbBlobVersionTooNewError");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBlobVersionTooNew);
            REQUIRE(dynamic_cast<const itb::ItbBlobVersionTooNewError*>(&e)
                    != nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobMalformedError*>(&e)
                    == nullptr);
            REQUIRE(dynamic_cast<const itb::ItbBlobModeMismatchError*>(&e)
                    == nullptr);
        }
    }
}

// ─── what() payload sanity across the three blob exceptions ───────

TEST_CASE("Blob exception what() carries the libitb status name",
          "[blob-errors][what]") {
    SECTION("ItbBlobModeMismatchError") {
        auto blob = make_single_blob();
        itb::Blob256 receiver{};
        try {
            receiver.import_triple(blob);
            FAIL("expected ItbBlobModeMismatchError");
        } catch (const std::exception& e) {
            const std::string what{e.what()};
            REQUIRE(what.find("BLOB_MODE_MISMATCH") != std::string::npos);
        }
    }
    SECTION("ItbBlobMalformedError") {
        auto bad = bytes_of("not json at all");
        itb::Blob256 receiver{};
        try {
            receiver.import_blob(bad);
            FAIL("expected ItbBlobMalformedError");
        } catch (const std::exception& e) {
            const std::string what{e.what()};
            REQUIRE(what.find("BLOB_MALFORMED") != std::string::npos);
        }
    }
    SECTION("ItbBlobVersionTooNewError") {
        auto blob = bytes_of(kTooNewBlob512);
        itb::Blob512 receiver{};
        try {
            receiver.import_blob(blob);
            FAIL("expected ItbBlobVersionTooNewError");
        } catch (const std::exception& e) {
            const std::string what{e.what()};
            REQUIRE(what.find("BLOB_VERSION_TOO_NEW") != std::string::npos);
        }
    }
}

// ─── Cross-class dynamic_cast: the three subtypes are distinct ────

TEST_CASE("Blob exception subtypes are distinct types under dynamic_cast",
          "[blob-errors][distinctness]") {
    itb::ItbBlobModeMismatchError mode_err{};
    itb::ItbBlobMalformedError    mal_err{};
    itb::ItbBlobVersionTooNewError ver_err{};

    REQUIRE(dynamic_cast<itb::ItbBlobMalformedError*>(
                static_cast<itb::ItbError*>(&mode_err)) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobVersionTooNewError*>(
                static_cast<itb::ItbError*>(&mode_err)) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobModeMismatchError*>(
                static_cast<itb::ItbError*>(&mal_err)) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobVersionTooNewError*>(
                static_cast<itb::ItbError*>(&mal_err)) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobModeMismatchError*>(
                static_cast<itb::ItbError*>(&ver_err)) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobMalformedError*>(
                static_cast<itb::ItbError*>(&ver_err)) == nullptr);
}
