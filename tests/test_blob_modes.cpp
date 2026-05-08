// test_blob_modes.cpp — mode discrimination across Blob128/256/512.
//
// Covers the Single-vs-Triple mode discrimination contract. A blob
// produced by `export_blob()` is a Single-mode blob; `import_blob()`
// accepts it but `import_triple()` raises ItbBlobModeMismatchError
// (and vice versa). Mode tracking is verified across all three widths:
// fresh handle reports mode 0, post-import_blob reports 1,
// post-import_triple reports 3.
//
// Cross-width import behaviour is exercised once and the observed
// status is recorded as a fact about the C-binding's surface — the
// test does not pre-judge whether BAD_INPUT or MALFORMED is the
// correct code; the C binding is the source of truth and the test
// asserts that *some* ItbError is raised (the exception type is the
// load-bearing part) plus dynamic_cast distinguishes the three blob
// exception subtypes.
//
// Mirrors bindings/c/tests/test_blob.c::test_blob_mode_mismatch +
// the construct-each-width pattern, adapted to Catch2 v3.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// Builds a minimal valid Single blob on the given Blob<W>. Caller
// supplies the primitive + key_bits + width-matched factory.
std::vector<std::uint8_t> single_blob_blake3() {
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

std::vector<std::uint8_t> triple_blob_blake3() {
    itb::Seed ns{"blake3", 1024};
    itb::Seed d1{"blake3", 1024};
    itb::Seed d2{"blake3", 1024};
    itb::Seed d3{"blake3", 1024};
    itb::Seed s1{"blake3", 1024};
    itb::Seed s2{"blake3", 1024};
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

} // namespace

// ─── Mode field on a fresh handle is 0 across all three widths ─────

TEST_CASE("Fresh blob handles report mode 0 across all widths",
          "[modes][fresh]") {
    itb::Blob128 b1{};
    itb::Blob256 b2{};
    itb::Blob512 b3{};
    REQUIRE(b1.mode() == 0);
    REQUIRE(b2.mode() == 0);
    REQUIRE(b3.mode() == 0);
    REQUIRE(b1.width() == 128);
    REQUIRE(b2.width() == 256);
    REQUIRE(b3.width() == 512);
}

// ─── export_blob → import_blob OK; import_triple raises mismatch ───

TEST_CASE("export_blob produces a Single blob; import_triple rejects",
          "[modes][single→triple-mismatch]") {
    auto blob = single_blob_blake3();

    SECTION("import_blob accepts and reports mode == 1") {
        itb::Blob256 receiver{};
        receiver.import_blob(blob);
        REQUIRE(receiver.mode() == 1);
    }
    SECTION("import_triple raises ItbBlobModeMismatchError") {
        itb::Blob256 receiver{};
        try {
            receiver.import_triple(blob);
            FAIL("expected ItbBlobModeMismatchError");
        } catch (const itb::ItbBlobModeMismatchError& e) {
            REQUIRE(e.code() == itb::status::kBlobModeMismatch);
        }
    }
}

// ─── export_triple → import_triple OK; import_blob raises mismatch ─

TEST_CASE("export_triple produces a Triple blob; import_blob rejects",
          "[modes][triple→single-mismatch]") {
    auto blob = triple_blob_blake3();

    SECTION("import_triple accepts and reports mode == 3") {
        itb::Blob256 receiver{};
        receiver.import_triple(blob);
        REQUIRE(receiver.mode() == 3);
    }
    SECTION("import_blob raises ItbBlobModeMismatchError") {
        itb::Blob256 receiver{};
        try {
            receiver.import_blob(blob);
            FAIL("expected ItbBlobModeMismatchError");
        } catch (const itb::ItbBlobModeMismatchError& e) {
            REQUIRE(e.code() == itb::status::kBlobModeMismatch);
        }
    }
}

// ─── Mode advances 0 → 1 / 0 → 3 on the receiver side, all widths ──

TEST_CASE("Blob128 receiver mode advances correctly across import paths",
          "[modes][blob128]") {
    SECTION("import_blob → 1") {
        itb::Seed ns{"siphash24", 512};
        itb::Seed ds{"siphash24", 512};
        itb::Seed ss{"siphash24", 512};
        itb::Blob128 sender{};
        sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
        sender.set_components(itb::blob::Slot::Noise, ns.components());
        sender.set_key(itb::blob::Slot::Data, ds.hash_key());
        sender.set_components(itb::blob::Slot::Data, ds.components());
        sender.set_key(itb::blob::Slot::Start, ss.hash_key());
        sender.set_components(itb::blob::Slot::Start, ss.components());
        auto blob = sender.export_blob(itb::blob::None);

        itb::Blob128 receiver{};
        REQUIRE(receiver.mode() == 0);
        receiver.import_blob(blob);
        REQUIRE(receiver.mode() == 1);
    }
    SECTION("import_triple → 3") {
        const char* p = "siphash24";
        itb::Seed ns{p, 512}, d1{p, 512}, d2{p, 512}, d3{p, 512};
        itb::Seed s1{p, 512}, s2{p, 512}, s3{p, 512};
        itb::Blob128 sender{};
        sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
        sender.set_components(itb::blob::Slot::Noise, ns.components());
        sender.set_key(itb::blob::Slot::Data1, d1.hash_key());
        sender.set_components(itb::blob::Slot::Data1, d1.components());
        sender.set_key(itb::blob::Slot::Data2, d2.hash_key());
        sender.set_components(itb::blob::Slot::Data2, d2.components());
        sender.set_key(itb::blob::Slot::Data3, d3.hash_key());
        sender.set_components(itb::blob::Slot::Data3, d3.components());
        sender.set_key(itb::blob::Slot::Start1, s1.hash_key());
        sender.set_components(itb::blob::Slot::Start1, s1.components());
        sender.set_key(itb::blob::Slot::Start2, s2.hash_key());
        sender.set_components(itb::blob::Slot::Start2, s2.components());
        sender.set_key(itb::blob::Slot::Start3, s3.hash_key());
        sender.set_components(itb::blob::Slot::Start3, s3.components());
        auto blob = sender.export_triple(itb::blob::None);

        itb::Blob128 receiver{};
        REQUIRE(receiver.mode() == 0);
        receiver.import_triple(blob);
        REQUIRE(receiver.mode() == 3);
    }
}

TEST_CASE("Blob512 receiver mode advances correctly across import paths",
          "[modes][blob512]") {
    SECTION("import_blob → 1") {
        const char* p = "areion512";
        itb::Seed ns{p, 1024}, ds{p, 1024}, ss{p, 1024};
        itb::Blob512 sender{};
        sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
        sender.set_components(itb::blob::Slot::Noise, ns.components());
        sender.set_key(itb::blob::Slot::Data, ds.hash_key());
        sender.set_components(itb::blob::Slot::Data, ds.components());
        sender.set_key(itb::blob::Slot::Start, ss.hash_key());
        sender.set_components(itb::blob::Slot::Start, ss.components());
        auto blob = sender.export_blob(itb::blob::None);

        itb::Blob512 receiver{};
        receiver.import_blob(blob);
        REQUIRE(receiver.mode() == 1);
    }
    SECTION("import_triple → 3") {
        const char* p = "areion512";
        itb::Seed ns{p, 1024}, d1{p, 1024}, d2{p, 1024}, d3{p, 1024};
        itb::Seed s1{p, 1024}, s2{p, 1024}, s3{p, 1024};
        itb::Blob512 sender{};
        sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
        sender.set_components(itb::blob::Slot::Noise, ns.components());
        sender.set_key(itb::blob::Slot::Data1, d1.hash_key());
        sender.set_components(itb::blob::Slot::Data1, d1.components());
        sender.set_key(itb::blob::Slot::Data2, d2.hash_key());
        sender.set_components(itb::blob::Slot::Data2, d2.components());
        sender.set_key(itb::blob::Slot::Data3, d3.hash_key());
        sender.set_components(itb::blob::Slot::Data3, d3.components());
        sender.set_key(itb::blob::Slot::Start1, s1.hash_key());
        sender.set_components(itb::blob::Slot::Start1, s1.components());
        sender.set_key(itb::blob::Slot::Start2, s2.hash_key());
        sender.set_components(itb::blob::Slot::Start2, s2.components());
        sender.set_key(itb::blob::Slot::Start3, s3.hash_key());
        sender.set_components(itb::blob::Slot::Start3, s3.components());
        auto blob = sender.export_triple(itb::blob::None);

        itb::Blob512 receiver{};
        receiver.import_triple(blob);
        REQUIRE(receiver.mode() == 3);
    }
}

// ─── Cross-width import behaviour is recorded (not pre-judged). The
//     C binding's blob importer parses width-agnostic JSON; importing
//     a blob produced under one width into a receiver handle of a
//     different width does not raise an ItbError. The receiver's
//     `width()` remains its native width (the constant baked in at
//     handle construction); the slot data is stored verbatim from
//     the JSON. The test pins this empirical behaviour so a future
//     binding-side regression that starts rejecting cross-width
//     imports surfaces here.

TEST_CASE("Cross-width import — Blob256 bytes into a Blob128 receiver — succeeds",
          "[modes][cross-width]") {
    auto blob = single_blob_blake3(); // produced from a Blob256

    itb::Blob128 receiver{};
    REQUIRE_NOTHROW(receiver.import_blob(blob));
    // Receiver's native width is fixed at construction time and does
    // not adopt the blob's embedded key_bits.
    REQUIRE(receiver.width() == 128);
    REQUIRE(receiver.mode() == 1);
}

// ─── The three Blob exception subtypes are distinct types. dynamic_cast
//     between them returns nullptr; only the matching subtype unwraps.

TEST_CASE("ItbBlobModeMismatchError is a distinct type from the malformed/version peers",
          "[modes][exception-distinctness]") {
    itb::ItbBlobModeMismatchError mode_err{};
    itb::ItbBlobMalformedError    mal_err{};
    itb::ItbBlobVersionTooNewError ver_err{};

    // Each subtype's address as an ItbError* — dynamic_cast back to
    // a *different* subtype must return nullptr.
    itb::ItbError* base_mode = &mode_err;
    itb::ItbError* base_mal  = &mal_err;
    itb::ItbError* base_ver  = &ver_err;

    REQUIRE(dynamic_cast<itb::ItbBlobModeMismatchError*>(base_mal) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobModeMismatchError*>(base_ver) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobMalformedError*>(base_mode)   == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobMalformedError*>(base_ver)    == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobVersionTooNewError*>(base_mode) == nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobVersionTooNewError*>(base_mal)  == nullptr);

    // Each subtype dynamic_casts back to itself successfully.
    REQUIRE(dynamic_cast<itb::ItbBlobModeMismatchError*>(base_mode) != nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobMalformedError*>(base_mal)     != nullptr);
    REQUIRE(dynamic_cast<itb::ItbBlobVersionTooNewError*>(base_ver) != nullptr);

    // All three are also catchable via the ItbError base interface.
    REQUIRE(base_mode->code() == itb::status::kBlobModeMismatch);
    REQUIRE(base_mal->code()  == itb::status::kBlobMalformed);
    REQUIRE(base_ver->code()  == itb::status::kBlobVersionTooNew);
}

// ─── Mode-mismatch is catchable via the base ItbError + std::exception ─

TEST_CASE("Mode-mismatch exception is catchable via base ItbError and std::exception",
          "[modes][catch-hierarchy]") {
    auto blob = single_blob_blake3();

    SECTION("catch as ItbError") {
        itb::Blob256 receiver{};
        try {
            receiver.import_triple(blob);
            FAIL("expected exception");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kBlobModeMismatch);
            // Confirm the underlying type is the typed subclass.
            REQUIRE(dynamic_cast<const itb::ItbBlobModeMismatchError*>(&e) != nullptr);
        }
    }
    SECTION("catch as std::exception") {
        itb::Blob256 receiver{};
        try {
            receiver.import_triple(blob);
            FAIL("expected exception");
        } catch (const std::exception& e) {
            // what() includes the human-readable status name.
            const std::string what{e.what()};
            REQUIRE(what.find("BLOB_MODE_MISMATCH") != std::string::npos);
        }
    }
}
