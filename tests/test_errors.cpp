// test_errors.cpp — exception hierarchy + status namespace coverage.
//
// Covers the five public exception classes (`ItbError` and the four
// subclasses `ItbEasyMismatchError`, `ItbBlobModeMismatchError`,
// `ItbBlobMalformedError`, `ItbBlobVersionTooNewError`), the
// `itb::status::name(int)` round-trip across every defined status
// code plus the "unknown" sentinel, the `detail::check` /
// `detail::throw_from_status` dispatch helper, the `what()` payload
// format ("itb: NAME (code): message"), and the free-function
// diagnostic accessors `itb::last_error` / `itb::last_mismatch_field`.
//
// Mirrors patterns from bindings/rust/tests/test_easy_persistence.rs
// and the polymorphic-catch idioms exercised in
// bindings/c/tests/test_easy_persistence.c, adapted to Catch2 v3.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Build a baseline blob suitable for triggering EASY_MISMATCH on a
// receiver constructed with a different primitive / key_bits / mode /
// mac. The resulting blob is also a useful "OK" fixture for the TLS
// post-success probe at the end of the file.
std::vector<std::uint8_t> baseline_blob() {
    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    return src.export_state();
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

} // namespace

// ─── ItbError direct construction ──────────────────────────────────

TEST_CASE("ItbError two-arg ctor stores code and message",
          "[errors][base]") {
    itb::ItbError e{itb::status::kBadInput, "explicit message"};
    REQUIRE(e.code() == itb::status::kBadInput);
    REQUIRE(e.message() == "explicit message");
    REQUIRE(e.name() == "BAD_INPUT");
    const std::string what{e.what()};
    REQUIRE(contains(what, "itb: "));
    REQUIRE(contains(what, "BAD_INPUT"));
    REQUIRE(contains(what, std::to_string(itb::status::kBadInput)));
    REQUIRE(contains(what, "explicit message"));
}

TEST_CASE("ItbError one-arg ctor reads thread-local diagnostic",
          "[errors][base]") {
    // The single-arg constructor consults `itb::last_error()` at
    // construction time. With no in-flight failure on this thread the
    // diagnostic is permitted to be empty; only the structural fields
    // are pinned.
    itb::ItbError e{itb::status::kEncryptFailed};
    REQUIRE(e.code() == itb::status::kEncryptFailed);
    REQUIRE(e.name() == "ENCRYPT_FAILED");
    const std::string what{e.what()};
    REQUIRE(contains(what, "itb: "));
    REQUIRE(contains(what, "ENCRYPT_FAILED"));
    REQUIRE(contains(what, std::to_string(itb::status::kEncryptFailed)));
}

TEST_CASE("ItbError what() omits trailing colon when message is empty",
          "[errors][base][what]") {
    itb::ItbError e{itb::status::kInternal, ""};
    const std::string what{e.what()};
    REQUIRE(contains(what, "INTERNAL"));
    // The format is "itb: NAME (code)" with no trailing ": " when the
    // message is empty. Pin only the absence of a trailing colon-space
    // — otherwise the substring "itb: " (the prefix) would create a
    // false positive.
    REQUIRE_FALSE(what.empty());
    REQUIRE(what.back() != ' ');
    REQUIRE(what.back() != ':');
}

// ─── Subclass constructors ─────────────────────────────────────────

TEST_CASE("ItbEasyMismatchError carries field and code",
          "[errors][mismatch]") {
    SECTION("two-arg constructor") {
        itb::ItbEasyMismatchError e{"primitive", "blake3 vs blake2s"};
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "primitive");
        REQUIRE(e.message() == "blake3 vs blake2s");
        REQUIRE(e.name() == "EASY_MISMATCH");
    }
    SECTION("one-arg constructor (message from libitb TLS)") {
        itb::ItbEasyMismatchError e{"key_bits"};
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "key_bits");
    }
}

TEST_CASE("ItbBlobModeMismatchError default ctor reports correct code",
          "[errors][blob]") {
    itb::ItbBlobModeMismatchError e;
    REQUIRE(e.code() == itb::status::kBlobModeMismatch);
    REQUIRE(e.name() == "BLOB_MODE_MISMATCH");
}

TEST_CASE("ItbBlobMalformedError default ctor reports correct code",
          "[errors][blob]") {
    itb::ItbBlobMalformedError e;
    REQUIRE(e.code() == itb::status::kBlobMalformed);
    REQUIRE(e.name() == "BLOB_MALFORMED");
}

TEST_CASE("ItbBlobVersionTooNewError default ctor reports correct code",
          "[errors][blob]") {
    itb::ItbBlobVersionTooNewError e;
    REQUIRE(e.code() == itb::status::kBlobVersionTooNew);
    REQUIRE(e.name() == "BLOB_VERSION_TOO_NEW");
}

// ─── Polymorphic catch ─────────────────────────────────────────────

TEST_CASE("ItbEasyMismatchError caught via ItbError base + dynamic_cast",
          "[errors][hierarchy][mismatch]") {
    try {
        throw itb::ItbEasyMismatchError{"primitive", "msg"};
    } catch (const itb::ItbError& base) {
        REQUIRE(base.code() == itb::status::kEasyMismatch);
        const auto* sub = dynamic_cast<const itb::ItbEasyMismatchError*>(&base);
        REQUIRE(sub != nullptr);
        REQUIRE(sub->field() == "primitive");
    }
}

TEST_CASE("ItbBlobModeMismatchError caught via ItbError base + dynamic_cast",
          "[errors][hierarchy][blob]") {
    try {
        throw itb::ItbBlobModeMismatchError{};
    } catch (const itb::ItbError& base) {
        REQUIRE(base.code() == itb::status::kBlobModeMismatch);
        const auto* sub = dynamic_cast<const itb::ItbBlobModeMismatchError*>(&base);
        REQUIRE(sub != nullptr);
    }
}

TEST_CASE("ItbBlobMalformedError caught via ItbError base + dynamic_cast",
          "[errors][hierarchy][blob]") {
    try {
        throw itb::ItbBlobMalformedError{};
    } catch (const itb::ItbError& base) {
        REQUIRE(base.code() == itb::status::kBlobMalformed);
        const auto* sub = dynamic_cast<const itb::ItbBlobMalformedError*>(&base);
        REQUIRE(sub != nullptr);
    }
}

TEST_CASE("ItbBlobVersionTooNewError caught via ItbError base + dynamic_cast",
          "[errors][hierarchy][blob]") {
    try {
        throw itb::ItbBlobVersionTooNewError{};
    } catch (const itb::ItbError& base) {
        REQUIRE(base.code() == itb::status::kBlobVersionTooNew);
        const auto* sub = dynamic_cast<const itb::ItbBlobVersionTooNewError*>(&base);
        REQUIRE(sub != nullptr);
    }
}

TEST_CASE("All five exception classes catchable via std::exception",
          "[errors][hierarchy][std]") {
    SECTION("ItbError") {
        try {
            throw itb::ItbError{itb::status::kBadInput, "x"};
        } catch (const std::exception& e) {
            REQUIRE(contains(e.what(), "BAD_INPUT"));
        }
    }
    SECTION("ItbEasyMismatchError") {
        try {
            throw itb::ItbEasyMismatchError{"primitive"};
        } catch (const std::exception& e) {
            REQUIRE(contains(e.what(), "EASY_MISMATCH"));
        }
    }
    SECTION("ItbBlobModeMismatchError") {
        try {
            throw itb::ItbBlobModeMismatchError{};
        } catch (const std::exception& e) {
            REQUIRE(contains(e.what(), "BLOB_MODE_MISMATCH"));
        }
    }
    SECTION("ItbBlobMalformedError") {
        try {
            throw itb::ItbBlobMalformedError{};
        } catch (const std::exception& e) {
            REQUIRE(contains(e.what(), "BLOB_MALFORMED"));
        }
    }
    SECTION("ItbBlobVersionTooNewError") {
        try {
            throw itb::ItbBlobVersionTooNewError{};
        } catch (const std::exception& e) {
            REQUIRE(contains(e.what(), "BLOB_VERSION_TOO_NEW"));
        }
    }
}

// ─── status::name round-trip for every defined code ────────────────

TEST_CASE("itb::status::name returns canonical string for every defined code",
          "[errors][status][names]") {
    REQUIRE(itb::status::name(itb::status::kOk)                       == "OK");
    REQUIRE(itb::status::name(itb::status::kBadHash)                  == "BAD_HASH");
    REQUIRE(itb::status::name(itb::status::kBadKeyBits)               == "BAD_KEY_BITS");
    REQUIRE(itb::status::name(itb::status::kBadHandle)                == "BAD_HANDLE");
    REQUIRE(itb::status::name(itb::status::kBadInput)                 == "BAD_INPUT");
    REQUIRE(itb::status::name(itb::status::kBufferTooSmall)           == "BUFFER_TOO_SMALL");
    REQUIRE(itb::status::name(itb::status::kEncryptFailed)            == "ENCRYPT_FAILED");
    REQUIRE(itb::status::name(itb::status::kDecryptFailed)            == "DECRYPT_FAILED");
    REQUIRE(itb::status::name(itb::status::kSeedWidthMix)             == "SEED_WIDTH_MIX");
    REQUIRE(itb::status::name(itb::status::kBadMac)                   == "BAD_MAC");
    REQUIRE(itb::status::name(itb::status::kMacFailure)               == "MAC_FAILURE");
    REQUIRE(itb::status::name(itb::status::kEasyClosed)               == "EASY_CLOSED");
    REQUIRE(itb::status::name(itb::status::kEasyMalformed)            == "EASY_MALFORMED");
    REQUIRE(itb::status::name(itb::status::kEasyVersionTooNew)        == "EASY_VERSION_TOO_NEW");
    REQUIRE(itb::status::name(itb::status::kEasyUnknownPrimitive)     == "EASY_UNKNOWN_PRIMITIVE");
    REQUIRE(itb::status::name(itb::status::kEasyUnknownMac)           == "EASY_UNKNOWN_MAC");
    REQUIRE(itb::status::name(itb::status::kEasyBadKeyBits)           == "EASY_BAD_KEY_BITS");
    REQUIRE(itb::status::name(itb::status::kEasyMismatch)             == "EASY_MISMATCH");
    REQUIRE(itb::status::name(itb::status::kEasyLockSeedAfterEncrypt) == "EASY_LOCKSEED_AFTER_ENCRYPT");
    REQUIRE(itb::status::name(itb::status::kBlobModeMismatch)         == "BLOB_MODE_MISMATCH");
    REQUIRE(itb::status::name(itb::status::kBlobMalformed)            == "BLOB_MALFORMED");
    REQUIRE(itb::status::name(itb::status::kBlobVersionTooNew)        == "BLOB_VERSION_TOO_NEW");
    REQUIRE(itb::status::name(itb::status::kBlobTooManyOpts)          == "BLOB_TOO_MANY_OPTS");
    REQUIRE(itb::status::name(itb::status::kInternal)                 == "INTERNAL");
}

TEST_CASE("itb::status::name returns 'unknown' for codes outside the defined set",
          "[errors][status][names][unknown]") {
    REQUIRE(itb::status::name(-1)    == "unknown");
    REQUIRE(itb::status::name(9999)  == "unknown");
    REQUIRE(itb::status::name(12345) == "unknown");
    REQUIRE(itb::status::name(-9999) == "unknown");
}

// ─── detail::check / throw_from_status dispatch ────────────────────

TEST_CASE("detail::check on ITB_OK does not throw",
          "[errors][dispatch][ok]") {
    REQUIRE_NOTHROW(itb::detail::check(itb::status::kOk));
}

TEST_CASE("detail::check dispatches EASY_MISMATCH to ItbEasyMismatchError",
          "[errors][dispatch][mismatch]") {
    try {
        itb::detail::check(itb::status::kEasyMismatch);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
    }
}

TEST_CASE("detail::check dispatches BLOB_MODE_MISMATCH to ItbBlobModeMismatchError",
          "[errors][dispatch][blob]") {
    try {
        itb::detail::check(itb::status::kBlobModeMismatch);
        FAIL("expected ItbBlobModeMismatchError");
    } catch (const itb::ItbBlobModeMismatchError& e) {
        REQUIRE(e.code() == itb::status::kBlobModeMismatch);
    }
}

TEST_CASE("detail::check dispatches BLOB_MALFORMED to ItbBlobMalformedError",
          "[errors][dispatch][blob]") {
    try {
        itb::detail::check(itb::status::kBlobMalformed);
        FAIL("expected ItbBlobMalformedError");
    } catch (const itb::ItbBlobMalformedError& e) {
        REQUIRE(e.code() == itb::status::kBlobMalformed);
    }
}

TEST_CASE("detail::check dispatches BLOB_VERSION_TOO_NEW to ItbBlobVersionTooNewError",
          "[errors][dispatch][blob]") {
    try {
        itb::detail::check(itb::status::kBlobVersionTooNew);
        FAIL("expected ItbBlobVersionTooNewError");
    } catch (const itb::ItbBlobVersionTooNewError& e) {
        REQUIRE(e.code() == itb::status::kBlobVersionTooNew);
    }
}

TEST_CASE("detail::check routes cold-path codes to plain ItbError",
          "[errors][dispatch][cold]") {
    auto require_plain = [](int code) {
        try {
            itb::detail::check(code);
            FAIL("expected ItbError");
        } catch (const itb::ItbEasyMismatchError&) {
            FAIL("unexpected ItbEasyMismatchError for cold-path code");
        } catch (const itb::ItbBlobModeMismatchError&) {
            FAIL("unexpected ItbBlobModeMismatchError for cold-path code");
        } catch (const itb::ItbBlobMalformedError&) {
            FAIL("unexpected ItbBlobMalformedError for cold-path code");
        } catch (const itb::ItbBlobVersionTooNewError&) {
            FAIL("unexpected ItbBlobVersionTooNewError for cold-path code");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == code);
        }
    };
    require_plain(itb::status::kBadInput);
    require_plain(itb::status::kBadHash);
    require_plain(itb::status::kBadKeyBits);
    require_plain(itb::status::kBadHandle);
    require_plain(itb::status::kBufferTooSmall);
    require_plain(itb::status::kEncryptFailed);
    require_plain(itb::status::kDecryptFailed);
    require_plain(itb::status::kSeedWidthMix);
    require_plain(itb::status::kBadMac);
    require_plain(itb::status::kMacFailure);
    require_plain(itb::status::kEasyClosed);
    require_plain(itb::status::kEasyMalformed);
    require_plain(itb::status::kEasyVersionTooNew);
    require_plain(itb::status::kEasyUnknownPrimitive);
    require_plain(itb::status::kEasyUnknownMac);
    require_plain(itb::status::kEasyBadKeyBits);
    require_plain(itb::status::kEasyLockSeedAfterEncrypt);
    require_plain(itb::status::kBlobTooManyOpts);
    require_plain(itb::status::kInternal);
}

// ─── last_error / last_mismatch_field free-function diagnostics ────

TEST_CASE("itb::last_error returns std::string (possibly empty)",
          "[errors][diag][last_error]") {
    // Cannot pin a specific string — TLS state is a side channel
    // observably mutated by every libitb call on this thread. The
    // contract is "type is std::string, never throws". Verify the
    // call returns successfully and does not raise.
    std::string s;
    REQUIRE_NOTHROW(s = itb::last_error());
    (void)s;
}

TEST_CASE("itb::last_mismatch_field returns a populated optional after import mismatch",
          "[errors][diag][last_mismatch_field]") {
    auto blob = baseline_blob();
    itb::Encryptor dst{"blake2s", 1024, "hmac-blake3", 1};
    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.field() == "primitive");
    }
    auto via_free = itb::last_mismatch_field();
    REQUIRE(via_free.has_value());
    REQUIRE(*via_free == "primitive");
}

TEST_CASE("itb::last_mismatch_field tolerates absence of a recent mismatch",
          "[errors][diag][last_mismatch_field][cold]") {
    // The TLS slot's content after a non-mismatch failure (or no
    // failure at all) is owned by libitb. The wrapper contract is
    // simply "return std::optional<std::string>" — accept either
    // nullopt or a stale residue without pinning a specific outcome.
    auto residue = itb::last_mismatch_field();
    SUCCEED("post-no-failure last_mismatch_field consulted; "
            "TLS semantics owned by libitb");
    (void)residue;
}
