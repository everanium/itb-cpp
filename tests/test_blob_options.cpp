// test_blob_options.cpp — export option flag combinations.
//
// Covers the four meaningful combinations of the export option
// bitmask: `None`, `LockSeed`, `Mac`, and `LockSeed | Mac`. The
// `LockSeed` flag triggers the `Slot::Lock` (slot index 3) inclusion
// in the JSON blob; `Mac` triggers MAC key + name. Both flags are
// independent — combining them must include both fragments without
// interfering with the Noise/Data/Start (or 7-slot Triple) base
// material.
//
// The combined-flag round-trip rebuilds the full Encryptor surface
// from the imported blob — Seeds via Seed::from_components and the
// Mac via the Mac constructor — then runs encrypt_auth +
// decrypt_auth to confirm the persisted material decrypts the
// original ciphertext. The Lock-slot material is verified at the
// per-slot byte level rather than fed into the cipher path; the
// bit-permutation overlay that activates the lock seed is gated by
// process-wide globals (set_bit_soup / set_lock_soup) which are
// owned by sibling test binaries.
//
// Process-wide globals (NonceBits / BarrierFill / BitSoup / LockSoup)
// are intentionally not mutated here — those are owned by sibling test
// binaries and would race them inside a shared process.
//
// Mirrors bindings/c/tests/test_blob.c::blob512_single_one /
// blob512_triple_one (the full-matrix helper) adapted to Catch2 v3.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0x0FF7AB1E0FF7AB1EULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr int kKeyBits = 1024;
constexpr const char* kPrim = "blake3";

} // namespace

// ─── Opt::None — minimal export ────────────────────────────────────

TEST_CASE("export_blob(None) emits no Lock slot, no MAC; receiver reports both empty",
          "[options][none]") {
    itb::Seed ns{kPrim, kKeyBits};
    itb::Seed ds{kPrim, kKeyBits};
    itb::Seed ss{kPrim, kKeyBits};

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());

    auto blob = sender.export_blob(itb::blob::None);
    REQUIRE_FALSE(blob.empty());

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);
    REQUIRE(receiver.get_mac_key().empty());
    REQUIRE(receiver.get_mac_name().empty());
    // Lock slot was not exported. The blob handle pre-allocates a
    // width-sized key buffer per slot regardless of whether the slot
    // was emitted by the exporter, so the absence-of-Lock signal is
    // carried by the component vector — which is unset for slots
    // that were not part of the exported JSON.
    REQUIRE(receiver.get_components(itb::blob::Slot::Lock).empty());
}

// ─── Opt::LockSeed — Single + dedicated lockSeed ───────────────────

TEST_CASE("export_blob(LockSeed) round-trips the dedicated Lock slot",
          "[options][lockseed]") {
    itb::Seed ns{kPrim, kKeyBits};
    itb::Seed ds{kPrim, kKeyBits};
    itb::Seed ss{kPrim, kKeyBits};
    itb::Seed lk{kPrim, kKeyBits};
    ns.attach_lock_seed(lk);

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());
    sender.set_key(itb::blob::Slot::Lock, lk.hash_key());
    sender.set_components(itb::blob::Slot::Lock, lk.components());

    auto blob = sender.export_blob(itb::blob::LockSeed);

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);
    REQUIRE(receiver.get_key(itb::blob::Slot::Lock) == lk.hash_key());
    REQUIRE(receiver.get_components(itb::blob::Slot::Lock) == lk.components());
}

// ─── Opt::Mac — Single + MAC key/name ──────────────────────────────

TEST_CASE("export_blob(Mac) round-trips the MAC key + name",
          "[options][mac]") {
    itb::Seed ns{kPrim, kKeyBits};
    itb::Seed ds{kPrim, kKeyBits};
    itb::Seed ss{kPrim, kKeyBits};

    std::vector<std::uint8_t> mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        mac_key[i] = static_cast<std::uint8_t>(0x42u ^ i);
    }

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    auto blob = sender.export_blob(itb::blob::Mac);

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);
    REQUIRE(receiver.get_mac_key() == mac_key);
    REQUIRE(receiver.get_mac_name() == "kmac256");
}

// ─── Opt::LockSeed | Opt::Mac — combined ───────────────────────────

TEST_CASE("export_blob(LockSeed | Mac) round-trips both options together",
          "[options][lockseed][mac][combined]") {
    itb::Seed ns{kPrim, kKeyBits};
    itb::Seed ds{kPrim, kKeyBits};
    itb::Seed ss{kPrim, kKeyBits};
    itb::Seed lk{kPrim, kKeyBits};
    ns.attach_lock_seed(lk);

    std::vector<std::uint8_t> mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        mac_key[i] = static_cast<std::uint8_t>(0x77u ^ i);
    }

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());
    sender.set_key(itb::blob::Slot::Lock, lk.hash_key());
    sender.set_components(itb::blob::Slot::Lock, lk.components());
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    int opts = itb::blob::LockSeed | itb::blob::Mac;
    auto blob = sender.export_blob(opts);

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);
    REQUIRE(receiver.get_key(itb::blob::Slot::Lock) == lk.hash_key());
    REQUIRE(receiver.get_components(itb::blob::Slot::Lock) == lk.components());
    REQUIRE(receiver.get_mac_key() == mac_key);
    REQUIRE(receiver.get_mac_name() == "kmac256");
}

// ─── Combined-flag end-to-end: rebuild Seeds + Mac + lockSeed and
//     decrypt a sentinel encrypted with the originals.
//
// The ciphertext is produced WITHOUT engaging the bit-permutation
// overlay (set_bit_soup / set_lock_soup are process-wide globals
// owned by sibling tests — mutating them here would race those
// tests). Consequently the lockSeed has no observable effect on the
// wire output and `attach_lock_seed` is intentionally not called on
// either the sender or receiver side. The Lock slot material still
// round-trips through the blob payload — the test confirms its
// per-slot fidelity AND that the encrypt/decrypt pair using the
// rebuilt non-Lock seeds + the rebuilt Mac succeeds end-to-end.

TEST_CASE("Combined LockSeed + Mac round-trip survives encrypt_auth → decrypt_auth",
          "[options][lockseed][mac][end-to-end]") {
    auto plaintext = token_bytes(2048);

    // Sender side — Lock slot is staged into the blob but not wired
    // into the noise seed (see comment above for the reason).
    itb::Seed ns{kPrim, kKeyBits};
    itb::Seed ds{kPrim, kKeyBits};
    itb::Seed ss{kPrim, kKeyBits};
    itb::Seed lk{kPrim, kKeyBits};

    std::vector<std::uint8_t> mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        mac_key[i] = static_cast<std::uint8_t>(0x99u ^ i);
    }
    itb::Mac mac{"kmac256", mac_key};

    auto ct = itb::encrypt_auth(ns, ds, ss, mac, plaintext);

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());
    sender.set_key(itb::blob::Slot::Lock, lk.hash_key());
    sender.set_components(itb::blob::Slot::Lock, lk.components());
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    auto blob = sender.export_blob(itb::blob::LockSeed | itb::blob::Mac);

    // Receiver side — rebuild every artefact from the imported blob.
    itb::Blob256 receiver{};
    receiver.import_blob(blob);

    auto ns2 = itb::Seed::from_components(
        kPrim,
        receiver.get_components(itb::blob::Slot::Noise),
        receiver.get_key(itb::blob::Slot::Noise));
    auto ds2 = itb::Seed::from_components(
        kPrim,
        receiver.get_components(itb::blob::Slot::Data),
        receiver.get_key(itb::blob::Slot::Data));
    auto ss2 = itb::Seed::from_components(
        kPrim,
        receiver.get_components(itb::blob::Slot::Start),
        receiver.get_key(itb::blob::Slot::Start));

    // Confirm the Lock slot round-tripped byte-faithfully.
    REQUIRE(receiver.get_key(itb::blob::Slot::Lock) == lk.hash_key());
    REQUIRE(receiver.get_components(itb::blob::Slot::Lock) == lk.components());

    itb::Mac mac2{"kmac256", receiver.get_mac_key()};

    auto pt = itb::decrypt_auth(ns2, ds2, ss2, mac2, ct);
    REQUIRE(pt == plaintext);
}

// ─── Triple variant of the combined-flag end-to-end pass ──────────
//
// Same scoping rule as the Single variant above — `attach_lock_seed`
// is intentionally skipped on both sides; the Lock slot round-trips
// as inert data and is verified at the slot-fidelity level rather
// than as cipher input.

TEST_CASE("Triple combined LockSeed + Mac round-trip survives encrypt_auth_triple",
          "[options][triple][lockseed][mac][end-to-end]") {
    auto plaintext = token_bytes(2048);

    itb::Seed ns {kPrim, kKeyBits};
    itb::Seed d1 {kPrim, kKeyBits};
    itb::Seed d2 {kPrim, kKeyBits};
    itb::Seed d3 {kPrim, kKeyBits};
    itb::Seed s1 {kPrim, kKeyBits};
    itb::Seed s2 {kPrim, kKeyBits};
    itb::Seed s3 {kPrim, kKeyBits};
    itb::Seed lk {kPrim, kKeyBits};

    std::vector<std::uint8_t> mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        mac_key[i] = static_cast<std::uint8_t>(0xa3u ^ i);
    }
    itb::Mac mac{"kmac256", mac_key};

    auto ct = itb::encrypt_auth_triple(ns, d1, d2, d3, s1, s2, s3, mac,
                                       plaintext);

    itb::Blob256 sender{};
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
    sender.set_key(itb::blob::Slot::Lock, lk.hash_key());
    sender.set_components(itb::blob::Slot::Lock, lk.components());
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    auto blob = sender.export_triple(itb::blob::LockSeed | itb::blob::Mac);

    itb::Blob256 receiver{};
    receiver.import_triple(blob);

    auto rebuild = [&](itb::blob::Slot slot) {
        return itb::Seed::from_components(
            kPrim,
            receiver.get_components(slot),
            receiver.get_key(slot));
    };
    auto ns2 = rebuild(itb::blob::Slot::Noise);
    auto d12 = rebuild(itb::blob::Slot::Data1);
    auto d22 = rebuild(itb::blob::Slot::Data2);
    auto d32 = rebuild(itb::blob::Slot::Data3);
    auto s12 = rebuild(itb::blob::Slot::Start1);
    auto s22 = rebuild(itb::blob::Slot::Start2);
    auto s32 = rebuild(itb::blob::Slot::Start3);

    REQUIRE(receiver.get_key(itb::blob::Slot::Lock) == lk.hash_key());
    REQUIRE(receiver.get_components(itb::blob::Slot::Lock) == lk.components());

    itb::Mac mac2{"kmac256", receiver.get_mac_key()};

    auto pt = itb::decrypt_auth_triple(ns2, d12, d22, d32, s12, s22, s32,
                                       mac2, ct);
    REQUIRE(pt == plaintext);
}
