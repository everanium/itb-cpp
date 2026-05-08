// test_last_mismatch_field.cpp — itb::last_mismatch_field free
// function coverage.
//
// Focuses on the FREE-FUNCTION accessor. After import_state surfaces
// ItbEasyMismatchError, the offending JSON field name is reachable
// via two paths: the exception's .field() member, and the free
// function itb::last_mismatch_field(). Both must agree.
//
// The full hierarchy round-trip (export + import on a matching
// encryptor) is covered separately. This file probes the four
// individual mismatch fields (primitive / key_bits / mode / mac) plus
// the post-success state of the TLS slot.
//
// Mirrors the import-mismatch subset of
// bindings/c/tests/test_easy_persistence.c.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> make_baseline_blob() {
    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    return src.export_state();
}

} // namespace

TEST_CASE("import_state primitive mismatch — exception + free function",
          "[mismatch][primitive]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake2s", 1024, "hmac-blake3", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "primitive");
        auto via_free = itb::last_mismatch_field();
        REQUIRE(via_free.has_value());
        REQUIRE(*via_free == "primitive");
    }
}

TEST_CASE("import_state key_bits mismatch — exception + free function",
          "[mismatch][key_bits]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake3", 2048, "hmac-blake3", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "key_bits");
        auto via_free = itb::last_mismatch_field();
        REQUIRE(via_free.has_value());
        REQUIRE(*via_free == "key_bits");
    }
}

TEST_CASE("import_state mode mismatch — exception + free function",
          "[mismatch][mode]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 3};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "mode");
        auto via_free = itb::last_mismatch_field();
        REQUIRE(via_free.has_value());
        REQUIRE(*via_free == "mode");
    }
}

TEST_CASE("import_state mac mismatch — exception + free function",
          "[mismatch][mac]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake3", 1024, "hmac-sha256", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "mac");
        auto via_free = itb::last_mismatch_field();
        REQUIRE(via_free.has_value());
        REQUIRE(*via_free == "mac");
    }
}

TEST_CASE("ItbError base catch still exposes mismatch field via free function",
          "[mismatch][polymorphic]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake2s", 1024, "hmac-blake3", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbError");
    } catch (const itb::ItbError& e) {
        // Caller that catches by base class can still read the field
        // through the free-function accessor.
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        auto via_free = itb::last_mismatch_field();
        REQUIRE(via_free.has_value());
        REQUIRE(*via_free == "primitive");
    }
}

TEST_CASE("successful import_state does not raise — TLS field semantics",
          "[mismatch][tls]") {
    auto blob = make_baseline_blob();
    itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 1};
    REQUIRE_NOTHROW(dst.import_state(blob));
    // libitb does not clear the per-thread mismatch slot on a
    // successful import; the wrapper exposes whatever libitb's TLS
    // slot currently holds. Either nullopt or a stale residue is
    // contractually permitted; do not pin a specific outcome here.
    auto residue = itb::last_mismatch_field();
    SUCCEED("post-success last_mismatch_field consulted; "
            "TLS semantics owned by libitb");
    (void)residue;
}
