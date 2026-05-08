// test_blob256.cpp — Blob256 width-specific persistence coverage.
//
// Width-typed binary-blob serialisation surface for the five 256-bit
// primitives `blake3` / `blake2s` / `blake2b256` / `chacha20` /
// `areion256`. Exercises the Single + Triple round-trip path (pack
// each Seed's hash key + components into a Blob256, export, import
// into a fresh handle, rebuild via Seed::from_components, decrypt the
// sentinel) plus a MAC + key persistence pass (pack a Mac key + name
// alongside the Seeds, export with the MAC option flag, import,
// rebuild the Mac, decrypt_auth a sentinel encrypted with the
// originals).
//
// Process-wide globals (NonceBits / BarrierFill / BitSoup / LockSoup)
// are intentionally not mutated here — those are owned by sibling test
// binaries and would race them inside a shared process.
//
// Mirrors bindings/c/tests/test_blob.c::test_blob_blob256_single +
// test_blob_blob256_triple, adapted to Catch2 v3 + the header-only
// C++ wrappers.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xB10B256B10B256B0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr int kKeyBits256 = 1024; // multiple of 256

// 5 primitives × 2 modes = 10 round-trip cases.
constexpr const char* kPrims256[] = {
    "blake3", "blake2s", "blake2b256", "chacha20", "areion256",
};

void single_roundtrip(const char* primitive,
                      const std::vector<std::uint8_t>& plaintext) {
    itb::Seed ns{primitive, kKeyBits256};
    itb::Seed ds{primitive, kKeyBits256};
    itb::Seed ss{primitive, kKeyBits256};

    auto ct = itb::encrypt(ns, ds, ss, plaintext);

    itb::Blob256 sender{};
    REQUIRE(sender.width() == 256);
    REQUIRE(sender.mode() == 0);

    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());

    auto blob = sender.export_blob(itb::blob::None);

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);

    auto ns2 = itb::Seed::from_components(
        primitive,
        receiver.get_components(itb::blob::Slot::Noise),
        receiver.get_key(itb::blob::Slot::Noise));
    auto ds2 = itb::Seed::from_components(
        primitive,
        receiver.get_components(itb::blob::Slot::Data),
        receiver.get_key(itb::blob::Slot::Data));
    auto ss2 = itb::Seed::from_components(
        primitive,
        receiver.get_components(itb::blob::Slot::Start),
        receiver.get_key(itb::blob::Slot::Start));

    auto pt = itb::decrypt(ns2, ds2, ss2, ct);
    REQUIRE(pt == plaintext);
}

void triple_roundtrip(const char* primitive,
                      const std::vector<std::uint8_t>& plaintext) {
    itb::Seed ns {primitive, kKeyBits256};
    itb::Seed d1 {primitive, kKeyBits256};
    itb::Seed d2 {primitive, kKeyBits256};
    itb::Seed d3 {primitive, kKeyBits256};
    itb::Seed s1 {primitive, kKeyBits256};
    itb::Seed s2 {primitive, kKeyBits256};
    itb::Seed s3 {primitive, kKeyBits256};

    auto ct = itb::encrypt_triple(ns, d1, d2, d3, s1, s2, s3, plaintext);

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

    auto blob = sender.export_triple(itb::blob::None);

    itb::Blob256 receiver{};
    receiver.import_triple(blob);
    REQUIRE(receiver.mode() == 3);

    auto rebuild = [&](itb::blob::Slot slot) {
        return itb::Seed::from_components(
            primitive,
            receiver.get_components(slot),
            receiver.get_key(slot));
    };
    auto ns2 = rebuild(itb::blob::Slot::Noise);
    auto d1_ = rebuild(itb::blob::Slot::Data1);
    auto d2_ = rebuild(itb::blob::Slot::Data2);
    auto d3_ = rebuild(itb::blob::Slot::Data3);
    auto s1_ = rebuild(itb::blob::Slot::Start1);
    auto s2_ = rebuild(itb::blob::Slot::Start2);
    auto s3_ = rebuild(itb::blob::Slot::Start3);

    auto pt = itb::decrypt_triple(ns2, d1_, d2_, d3_, s1_, s2_, s3_, ct);
    REQUIRE(pt == plaintext);
}

} // namespace

// ─── Construction + lifecycle ──────────────────────────────────────

TEST_CASE("Blob256 fresh-handle invariants",
          "[blob256][lifecycle]") {
    itb::Blob256 b{};
    REQUIRE(b.width() == 256);
    REQUIRE(b.mode() == 0);
    REQUIRE(b.raw_handle() != nullptr);
}

// ─── Direct slot-fidelity round-trip (no encrypt/decrypt path) ─────

TEST_CASE("Blob256 stages keys + components + MAC and round-trips slot bytes",
          "[blob256][slot-fidelity]") {
    std::vector<std::uint8_t> key_n(32), key_d(32), key_s(32), mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        key_n[i]   = static_cast<std::uint8_t>(0xa0u ^ i);
        key_d[i]   = static_cast<std::uint8_t>(0xb0u ^ i);
        key_s[i]   = static_cast<std::uint8_t>(0xc0u ^ i);
        mac_key[i] = static_cast<std::uint8_t>(0xd0u ^ i);
    }
    std::vector<std::uint64_t> comps_n(16), comps_d(16), comps_s(16);
    for (std::uint64_t i = 0; i < 16; i++) {
        comps_n[i] = 0x1000ULL + i;
        comps_d[i] = 0x2000ULL + i;
        comps_s[i] = 0x3000ULL + i;
    }

    itb::Blob256 sender{};
    sender.set_key(itb::blob::Slot::Noise, key_n);
    sender.set_components(itb::blob::Slot::Noise, comps_n);
    sender.set_key(itb::blob::Slot::Data, key_d);
    sender.set_components(itb::blob::Slot::Data, comps_d);
    sender.set_key(itb::blob::Slot::Start, key_s);
    sender.set_components(itb::blob::Slot::Start, comps_s);
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    auto blob = sender.export_blob(itb::blob::Mac);
    REQUIRE_FALSE(blob.empty());

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.width() == 256);
    REQUIRE(receiver.mode() == 1);

    REQUIRE(receiver.get_key(itb::blob::Slot::Noise) == key_n);
    REQUIRE(receiver.get_key(itb::blob::Slot::Data)  == key_d);
    REQUIRE(receiver.get_key(itb::blob::Slot::Start) == key_s);
    REQUIRE(receiver.get_components(itb::blob::Slot::Noise) == comps_n);
    REQUIRE(receiver.get_components(itb::blob::Slot::Data)  == comps_d);
    REQUIRE(receiver.get_components(itb::blob::Slot::Start) == comps_s);
    REQUIRE(receiver.get_mac_key() == mac_key);
    REQUIRE(receiver.get_mac_name() == "kmac256");
}

// ─── Single-mode round-trip × the five 256-bit primitives ─────────

TEST_CASE("Blob256 Single round-trip across the 256-bit primitive set",
          "[blob256][single][roundtrip]") {
    auto plaintext = token_bytes(512);
    for (const char* p : kPrims256) {
        SECTION(std::string{"primitive="} + p) {
            single_roundtrip(p, plaintext);
        }
    }
}

// ─── Triple-mode round-trip × the five 256-bit primitives ─────────

TEST_CASE("Blob256 Triple round-trip across the 256-bit primitive set",
          "[blob256][triple][roundtrip]") {
    auto plaintext = token_bytes(512);
    for (const char* p : kPrims256) {
        SECTION(std::string{"primitive="} + p) {
            triple_roundtrip(p, plaintext);
        }
    }
}

// ─── 32-byte fixed-key fidelity for blake3 + areion256 ────────────

TEST_CASE("Blob256 round-trips 32-byte fixed hash keys faithfully",
          "[blob256][hash-key-fidelity]") {
    SECTION("blake3 — 32-byte key") {
        itb::Seed s{"blake3", kKeyBits256};
        auto k = s.hash_key();
        REQUIRE(k.size() == 32);
        // Stage into a Blob256 + round-trip through export/import.
        itb::Blob256 sender{};
        sender.set_key(itb::blob::Slot::Noise, k);
        sender.set_components(itb::blob::Slot::Noise, s.components());
        // Need Data + Start slots populated for export to succeed —
        // synthesise them from another seed of the same primitive.
        itb::Seed ds{"blake3", kKeyBits256};
        itb::Seed ss{"blake3", kKeyBits256};
        sender.set_key(itb::blob::Slot::Data, ds.hash_key());
        sender.set_components(itb::blob::Slot::Data, ds.components());
        sender.set_key(itb::blob::Slot::Start, ss.hash_key());
        sender.set_components(itb::blob::Slot::Start, ss.components());

        auto blob = sender.export_blob(itb::blob::None);
        itb::Blob256 receiver{};
        receiver.import_blob(blob);
        REQUIRE(receiver.get_key(itb::blob::Slot::Noise) == k);
    }
    SECTION("areion256 — 32-byte key") {
        itb::Seed s{"areion256", kKeyBits256};
        auto k = s.hash_key();
        REQUIRE(k.size() == 32);
        itb::Blob256 sender{};
        sender.set_key(itb::blob::Slot::Noise, k);
        sender.set_components(itb::blob::Slot::Noise, s.components());
        itb::Seed ds{"areion256", kKeyBits256};
        itb::Seed ss{"areion256", kKeyBits256};
        sender.set_key(itb::blob::Slot::Data, ds.hash_key());
        sender.set_components(itb::blob::Slot::Data, ds.components());
        sender.set_key(itb::blob::Slot::Start, ss.hash_key());
        sender.set_components(itb::blob::Slot::Start, ss.components());

        auto blob = sender.export_blob(itb::blob::None);
        itb::Blob256 receiver{};
        receiver.import_blob(blob);
        REQUIRE(receiver.get_key(itb::blob::Slot::Noise) == k);
    }
}

// ─── Round-trip with MAC: encrypt_auth → blob → import → decrypt_auth ──

TEST_CASE("Blob256 round-trips MAC key + name end-to-end via encrypt_auth",
          "[blob256][mac][roundtrip]") {
    auto plaintext = token_bytes(1024);

    itb::Seed ns{"blake3", kKeyBits256};
    itb::Seed ds{"blake3", kKeyBits256};
    itb::Seed ss{"blake3", kKeyBits256};

    std::vector<std::uint8_t> mac_key(32);
    for (std::size_t i = 0; i < 32; i++) {
        mac_key[i] = static_cast<std::uint8_t>(0x55u ^ i);
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
    sender.set_mac_key(mac_key);
    sender.set_mac_name("kmac256");

    auto blob = sender.export_blob(itb::blob::Mac);

    itb::Blob256 receiver{};
    receiver.import_blob(blob);
    REQUIRE(receiver.mode() == 1);
    REQUIRE(receiver.get_mac_key() == mac_key);
    REQUIRE(receiver.get_mac_name() == "kmac256");

    auto ns2 = itb::Seed::from_components(
        "blake3",
        receiver.get_components(itb::blob::Slot::Noise),
        receiver.get_key(itb::blob::Slot::Noise));
    auto ds2 = itb::Seed::from_components(
        "blake3",
        receiver.get_components(itb::blob::Slot::Data),
        receiver.get_key(itb::blob::Slot::Data));
    auto ss2 = itb::Seed::from_components(
        "blake3",
        receiver.get_components(itb::blob::Slot::Start),
        receiver.get_key(itb::blob::Slot::Start));
    itb::Mac mac2{"kmac256", receiver.get_mac_key()};

    auto pt = itb::decrypt_auth(ns2, ds2, ss2, mac2, ct);
    REQUIRE(pt == plaintext);
}
