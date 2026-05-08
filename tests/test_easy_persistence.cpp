// test_persistence.cpp — full Encryptor state persistence coverage.
//
// Covers `Encryptor::export_state` / `Encryptor::import_state` /
// `peek_config` across the canonical 9 PRF primitives × 2 modes ×
// 2 MACs grid, the Mixed / Mixed3 per-slot persistence path
// (with and without the dedicated lockSeed slot), the peek-config
// happy path on both single-primitive and Mixed encryptors, the
// peek-config malformed-blob rejection, the transactional-import
// guarantee (a non-OK import leaves the receiver's pre-import
// state intact), and the closed-state preflight on `import_state`.
//
// Mirrors the persistence-roundtrip patterns from
// bindings/c/tests/test_easy_persistence.c +
// bindings/c/tests/test_easy_roundtrip.c, adapted to Catch2 v3.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct PrimSpec {
    const char* name;
    int width;
};

// Canonical 9-primitive set exposed through the Encryptor surface;
// width drives the key_bits-divisibility filter at the call site.
constexpr PrimSpec kPrims[] = {
    {"areion256",  256},
    {"areion512",  512},
    {"siphash24",  128},
    {"aescmac",    128},
    {"blake2b256", 256},
    {"blake2b512", 512},
    {"blake2s",    256},
    {"blake3",     256},
    {"chacha20",   256},
};

constexpr int kModes[] = {1, 3};
constexpr const char* kMacs[] = {"hmac-blake3", "kmac256"};

// Deterministic-but-varied plaintext so each test case observes a
// distinct payload.
std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xCAFEBABE12345678ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

} // namespace

// ─── Single-primitive round-trip across the full grid ──────────────

TEST_CASE("encryptor export/import round-trip across the full primitive grid",
          "[persistence][grid]") {
    auto plaintext = token_bytes(2048);
    for (const auto& spec : kPrims) {
        for (int mode : kModes) {
            // Restrict to a single canonical key_bits per primitive
            // (1024) — the alternate-key_bits axis is exercised in
            // Agent A's per-primitive suites. The persistence test
            // emphasises the matrix axis, not the key_bits axis.
            if (1024 % spec.width != 0) {
                continue;
            }
            for (const char* mac : kMacs) {
                SECTION(std::string{spec.name} + "/mode=" +
                        std::to_string(mode) + "/mac=" + mac) {
                    itb::Encryptor src{spec.name, 1024, mac, mode};
                    auto ct  = src.encrypt_auth(plaintext);
                    auto blob = src.export_state();

                    itb::Encryptor dst{spec.name, 1024, mac, mode};
                    REQUIRE_NOTHROW(dst.import_state(blob));
                    auto pt = dst.decrypt_auth(ct);
                    REQUIRE(pt == plaintext);
                }
            }
        }
    }
}

TEST_CASE("encryptor export/import round-trip with non-auth cipher",
          "[persistence][noauth]") {
    auto plaintext = token_bytes(1024);
    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    auto ct   = src.encrypt(plaintext);
    auto blob = src.export_state();

    itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 1};
    dst.import_state(blob);
    REQUIRE(dst.decrypt(ct) == plaintext);
}

TEST_CASE("encryptor export/import round-trip with lockSeed",
          "[persistence][lockseed]") {
    auto plaintext = token_bytes(512);

    SECTION("single + lockseed") {
        itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
        src.set_lock_seed(1);
        REQUIRE(src.seed_count() == 4);
        auto ct   = src.encrypt_auth(plaintext);
        auto blob = src.export_state();

        itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 1};
        REQUIRE(dst.seed_count() == 3); // before import
        dst.import_state(blob);
        REQUIRE(dst.seed_count() == 4); // restored
        REQUIRE(dst.decrypt_auth(ct) == plaintext);
    }
    SECTION("triple + lockseed") {
        itb::Encryptor src{"blake3", 1024, "hmac-blake3", 3};
        src.set_lock_seed(1);
        REQUIRE(src.seed_count() == 8);
        auto ct   = src.encrypt_auth(plaintext);
        auto blob = src.export_state();

        itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 3};
        REQUIRE(dst.seed_count() == 7); // before import
        dst.import_state(blob);
        REQUIRE(dst.seed_count() == 8); // restored
        REQUIRE(dst.decrypt_auth(ct) == plaintext);
    }
}

TEST_CASE("encryptor export/import restores per-instance configuration",
          "[persistence][config]") {
    auto plaintext = token_bytes(256);

    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    src.set_nonce_bits(512);
    src.set_barrier_fill(4);

    auto ct   = src.encrypt_auth(plaintext);
    auto blob = src.export_state();

    // Receiver — fresh encryptor without any mirror set_*() calls.
    itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 1};
    REQUIRE(dst.nonce_bits() == 128); // default
    dst.import_state(blob);
    REQUIRE(dst.nonce_bits() == 512); // restored
    REQUIRE(dst.decrypt_auth(ct) == plaintext);
}

// ─── Mixed / Mixed3 persistence ────────────────────────────────────

TEST_CASE("Mixed encryptor export/import round-trip without lockSeed",
          "[persistence][mixed][single]") {
    auto plaintext = token_bytes(1024);

    auto src = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "" /*no lockSeed*/, 1024, "hmac-blake3");
    auto ct   = src.encrypt_auth(plaintext);
    auto blob = src.export_state();

    auto dst = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "", 1024, "hmac-blake3");
    REQUIRE_NOTHROW(dst.import_state(blob));
    REQUIRE(dst.decrypt_auth(ct) == plaintext);
}

TEST_CASE("Mixed encryptor export/import round-trip with lockSeed",
          "[persistence][mixed][single][lockseed]") {
    auto plaintext = token_bytes(2048);

    auto src = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "areion256", 1024, "hmac-blake3");
    auto ct   = src.encrypt_auth(plaintext);
    auto blob = src.export_state();

    auto dst = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                     "areion256", 1024, "hmac-blake3");
    REQUIRE_NOTHROW(dst.import_state(blob));
    REQUIRE(dst.decrypt_auth(ct) == plaintext);
}

TEST_CASE("Mixed3 encryptor export/import round-trip without lockSeed",
          "[persistence][mixed3][triple]") {
    auto plaintext = token_bytes(2048);

    auto src = itb::Encryptor::Mixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "" /*no lockSeed*/, 1024, "hmac-blake3");
    auto ct   = src.encrypt_auth(plaintext);
    auto blob = src.export_state();

    auto dst = itb::Encryptor::Mixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "", 1024, "hmac-blake3");
    REQUIRE_NOTHROW(dst.import_state(blob));
    REQUIRE(dst.decrypt_auth(ct) == plaintext);
}

TEST_CASE("Mixed3 encryptor export/import round-trip with lockSeed",
          "[persistence][mixed3][triple][lockseed]") {
    auto plaintext = token_bytes(4096);

    auto src = itb::Encryptor::Mixed3(
        "blake3", "blake2s", "blake3", "blake2s",
        "blake3", "blake2s", "blake3",
        "areion256", 1024, "hmac-blake3");
    auto ct   = src.encrypt_auth(plaintext);
    auto blob = src.export_state();

    auto dst = itb::Encryptor::Mixed3(
        "blake3", "blake2s", "blake3", "blake2s",
        "blake3", "blake2s", "blake3",
        "areion256", 1024, "hmac-blake3");
    REQUIRE_NOTHROW(dst.import_state(blob));
    REQUIRE(dst.decrypt_auth(ct) == plaintext);
}

// ─── peek_config positive paths ────────────────────────────────────

TEST_CASE("peek_config recovers metadata from single-primitive blob",
          "[persistence][peek][single]") {
    for (const auto& spec : kPrims) {
        if (1024 % spec.width != 0) continue;
        for (int mode : kModes) {
            for (const char* mac : kMacs) {
                SECTION(std::string{spec.name} + "/mode=" +
                        std::to_string(mode) + "/mac=" + mac) {
                    itb::Encryptor enc{spec.name, 1024, mac, mode};
                    auto blob = enc.export_state();
                    auto cfg = itb::peek_config(blob);
                    REQUIRE(cfg.primitive == spec.name);
                    REQUIRE(cfg.key_bits == 1024);
                    REQUIRE(cfg.mode == mode);
                    REQUIRE(cfg.mac_name == mac);
                }
            }
        }
    }
}

TEST_CASE("peek_config recovers 'mixed' marker from Mixed encryptor blob",
          "[persistence][peek][mixed]") {
    SECTION("Mixed (single)") {
        auto enc = itb::Encryptor::Mixed("blake3", "blake2s", "blake2b256",
                                         "", 1024, "hmac-blake3");
        auto blob = enc.export_state();
        auto cfg = itb::peek_config(blob);
        REQUIRE(cfg.primitive == "mixed");
        REQUIRE(cfg.key_bits == 1024);
        REQUIRE(cfg.mode == 1);
        REQUIRE(cfg.mac_name == "hmac-blake3");
    }
    SECTION("Mixed3 (triple)") {
        auto enc = itb::Encryptor::Mixed3(
            "areion256", "blake3", "blake2s", "chacha20",
            "blake2b256", "blake3", "blake2s",
            "", 1024, "hmac-blake3");
        auto blob = enc.export_state();
        auto cfg = itb::peek_config(blob);
        REQUIRE(cfg.primitive == "mixed");
        REQUIRE(cfg.key_bits == 1024);
        REQUIRE(cfg.mode == 3);
        REQUIRE(cfg.mac_name == "hmac-blake3");
    }
}

TEST_CASE("peek_config rejects malformed blobs as ItbError(kEasyMalformed)",
          "[persistence][peek][malformed]") {
    auto must_fail = [](const std::vector<std::uint8_t>& bytes) {
        try {
            itb::peek_config(bytes);
            FAIL("expected ItbError(kEasyMalformed)");
        } catch (const itb::ItbError& e) {
            REQUIRE(e.code() == itb::status::kEasyMalformed);
        }
    };

    SECTION("plain text") {
        std::string_view sv = "not json";
        must_fail({reinterpret_cast<const std::uint8_t*>(sv.data()),
                   reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size())});
    }
    SECTION("empty bytes") {
        must_fail({});
    }
    SECTION("empty JSON object") {
        std::string_view sv = "{}";
        must_fail({reinterpret_cast<const std::uint8_t*>(sv.data()),
                   reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size())});
    }
    SECTION("only a version field") {
        std::string_view sv = "{\"v\":1}";
        must_fail({reinterpret_cast<const std::uint8_t*>(sv.data()),
                   reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size())});
    }
    SECTION("wrong kind tag") {
        std::string_view sv = "{\"v\":1,\"kind\":\"not-itb-easy\"}";
        must_fail({reinterpret_cast<const std::uint8_t*>(sv.data()),
                   reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size())});
    }
    SECTION("truncated valid blob") {
        // Take a real blob and chop it in half.
        itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
        auto blob = enc.export_state();
        REQUIRE(blob.size() > 4);
        blob.resize(blob.size() / 2);
        must_fail(blob);
    }
}

// ─── Transactional import (failed import does not corrupt receiver) ─

TEST_CASE("import_state failure leaves receiver state unchanged",
          "[persistence][transactional]") {
    // Source encryptor produces a blob with key_bits=1024.
    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    auto blob = src.export_state();

    // Receiver is constructed at key_bits=2048 — import must reject
    // with EASY_MISMATCH. After the throw the receiver's pre-import
    // state must still be operational: encrypt + decrypt round-trips
    // succeed using the receiver's freshly-generated keys.
    itb::Encryptor dst{"blake3", 2048, "hmac-blake3", 1};
    auto plaintext = token_bytes(128);
    auto ct_pre = dst.encrypt_auth(plaintext);
    REQUIRE(dst.decrypt_auth(ct_pre) == plaintext);

    try {
        dst.import_state(blob);
        FAIL("expected ItbEasyMismatchError");
    } catch (const itb::ItbEasyMismatchError& e) {
        REQUIRE(e.code() == itb::status::kEasyMismatch);
        REQUIRE(e.field() == "key_bits");
    }

    // Pre-import state intact — the receiver still encrypts /
    // decrypts using its own (untouched) keys.
    auto ct_post = dst.encrypt_auth(plaintext);
    REQUIRE(dst.decrypt_auth(ct_post) == plaintext);
}

TEST_CASE("import_state malformed-blob failure leaves receiver state unchanged",
          "[persistence][transactional][malformed]") {
    itb::Encryptor dst{"blake3", 1024, "hmac-blake3", 1};
    auto plaintext = token_bytes(64);
    auto ct_pre = dst.encrypt_auth(plaintext);
    REQUIRE(dst.decrypt_auth(ct_pre) == plaintext);

    static const char garbage[] = "this is definitely not a blob";
    const auto* p = reinterpret_cast<const std::uint8_t*>(garbage);
    std::vector<std::uint8_t> bad{p, p + sizeof(garbage) - 1};
    try {
        dst.import_state(bad);
        FAIL("expected ItbError(kEasyMalformed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyMalformed);
    }

    // Receiver still operational.
    auto ct_post = dst.encrypt_auth(plaintext);
    REQUIRE(dst.decrypt_auth(ct_post) == plaintext);
}

// ─── Closed-state preflight on import_state ────────────────────────

TEST_CASE("import_state on already-closed Encryptor raises kEasyClosed",
          "[persistence][closed]") {
    // Build a baseline blob from a separate source.
    itb::Encryptor src{"blake3", 1024, "hmac-blake3", 1};
    auto blob = src.export_state();

    itb::Encryptor enc{"blake3", 1024, "hmac-blake3", 1};
    enc.close();
    REQUIRE(enc.is_closed());

    try {
        enc.import_state(blob);
        FAIL("expected ItbError(kEasyClosed)");
    } catch (const itb::ItbError& e) {
        REQUIRE(e.code() == itb::status::kEasyClosed);
    }
}
