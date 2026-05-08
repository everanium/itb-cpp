// test_version_too_new.cpp — version-too-new error path differentiation.
//
// peek_config conflates "blob version too new" with the broader
// "blob malformed" bucket and surfaces ItbError(kEasyMalformed) for
// either condition. Encryptor::import_state is the only entry point
// that surfaces kEasyVersionTooNew distinctly.
//
// This file exercises both halves of that contract:
//   1) peek_config on a too-new-version blob raises
//      ItbError(kEasyMalformed).
//   2) import_state on the SAME blob raises
//      ItbError(kEasyVersionTooNew).
//
// Synthesis approach. The Easy state blob is encoded as JSON with a
// minimum shape carrying `"v":<int>` and `"kind":"itb-easy"`. The
// underlying libitb reader rejects blobs whose `v` exceeds the
// supported schema version BEFORE it parses the rest of the shape,
// so the smallest valid input that triggers the version-too-new path
// is the literal JSON `{"v":99,"kind":"itb-easy"}` — used here both
// as a hand-crafted byte literal and as a control fixture for the
// same-blob differentiation SECTION.
//
// The malformed-blob baseline (no version field, broken JSON, wrong
// kind tag) confirms that BOTH peek_config and import_state agree on
// the kEasyMalformed code, distinguishing the version-too-new
// asymmetry from the truly-malformed symmetry.
//
// Mirrors patterns from bindings/c/tests/test_easy_persistence.c
// (test_easy_persistence_peek_too_new_version +
// test_easy_persistence_import_too_new_version) and
// bindings/rust/tests/test_easy_persistence.rs
// (peek_too_new_version + import_too_new_version), adapted to
// Catch2 v3.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(s.data());
    return std::vector<std::uint8_t>{p, p + s.size()};
}

// The smallest blob shape that triggers the version-too-new path.
// Carries a valid kind tag + a v field higher than any libitb
// schema version the consumer supports.
const std::vector<std::uint8_t> kTooNewBlob =
    bytes_of(R"({"v":99,"kind":"itb-easy"})");

// Garbage: not JSON at all. Both peek and import classify as
// kEasyMalformed; the symmetry contrasts with the version-too-new
// asymmetry.
const std::vector<std::uint8_t> kBrokenJsonBlob =
    bytes_of("this is definitely not json");

// Wrong kind tag — JSON is well-formed but the tag does not match
// "itb-easy". Same kEasyMalformed code from both peek and import.
const std::vector<std::uint8_t> kWrongKindBlob =
    bytes_of(R"({"v":1,"kind":"not-itb-easy"})");

} // namespace

// ─── peek_config on the too-new blob ───────────────────────────────

TEST_CASE("peek_config conflates version-too-new with kEasyMalformed",
          "[version][peek]") {
    try {
        itb::peek_config(kTooNewBlob);
        FAIL("expected ItbError(kEasyMalformed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyMalformed);
    }
}

// ─── import_state on the too-new blob ──────────────────────────────

TEST_CASE("import_state on a too-new blob raises kEasyVersionTooNew",
          "[version][import]") {
    itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
    try {
        enc.import_state(kTooNewBlob);
        FAIL("expected ItbError(kEasyVersionTooNew)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyVersionTooNew);
    }
}

// ─── Same blob, two different reactions ────────────────────────────

TEST_CASE("peek_config conflates version-too-new with malformed; "
          "import_state differentiates",
          "[version][differentiation]") {
    // Step 1 — peek surfaces kEasyMalformed.
    SECTION("peek path → kEasyMalformed") {
        try {
            itb::peek_config(kTooNewBlob);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    }
    // Step 2 — import_state on the IDENTICAL blob surfaces a
    // distinct kEasyVersionTooNew code.
    SECTION("import path → kEasyVersionTooNew") {
        itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
        try {
            enc.import_state(kTooNewBlob);
            FAIL("expected ItbError(kEasyVersionTooNew)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyVersionTooNew);
        }
    }
}

// ─── Truly-malformed blobs: peek + import agree on kEasyMalformed ──

TEST_CASE("peek + import both raise kEasyMalformed for non-JSON garbage",
          "[version][malformed][garbage]") {
    SECTION("peek_config") {
        try {
            itb::peek_config(kBrokenJsonBlob);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    }
    SECTION("import_state") {
        itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
        try {
            enc.import_state(kBrokenJsonBlob);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    }
}

TEST_CASE("peek + import both raise kEasyMalformed for wrong kind tag",
          "[version][malformed][kind]") {
    SECTION("peek_config") {
        try {
            itb::peek_config(kWrongKindBlob);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    }
    SECTION("import_state") {
        itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
        try {
            enc.import_state(kWrongKindBlob);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    }
}
