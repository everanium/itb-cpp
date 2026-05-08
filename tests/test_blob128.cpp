// test_blob128.cpp — Blob128 width-specific persistence coverage.
//
// Width-typed binary-blob serialisation surface for the 128-bit
// primitives `siphash24` and `aescmac`. Exercises constructor /
// destructor / move semantics, the width / mode accessors, and the
// Single-Ouroboros + Triple-Ouroboros round-trip path: pack each Seed's
// hash key + components into a Blob128, export the JSON bytes, import
// into a fresh Blob128, rebuild the Seeds via Seed::from_components,
// and decrypt a sentinel ciphertext that was encrypted with the
// originals.
//
// Process-wide globals (NonceBits / BarrierFill / BitSoup / LockSoup)
// are intentionally not mutated here — those are owned by sibling test
// binaries and would race them inside a shared process.
//
// Mirrors bindings/c/tests/test_blob.c::test_blob_blob128_siphash_single
// and test_blob_blob128_aescmac_single, adapted to Catch2 v3 + the
// header-only C++ wrappers.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

// Deterministic counter-driven byte filler. Mirrors the splitmix-style
// generator used by sibling tests so payloads of a given length are
// reproducible across reruns within a single process.
std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xB10B128B10B128B1ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr int kKeyBits128 = 512; // multiple of 128 (siphash24 / aescmac)

// One-shot Single round-trip helper. Builds three Seeds at the
// 128-bit width, encrypts the plaintext, packs the seed material into
// a Blob128, exports + imports through a fresh handle, rebuilds the
// Seeds via from_components, decrypts, and asserts byte equality.
void single_roundtrip_via_blob128(const char* primitive,
                                  const std::vector<std::uint8_t>& plaintext) {
    itb::Seed ns{primitive, kKeyBits128};
    itb::Seed ds{primitive, kKeyBits128};
    itb::Seed ss{primitive, kKeyBits128};

    auto ct = itb::encrypt(ns, ds, ss, plaintext);

    itb::Blob128 sender{};
    REQUIRE(sender.width() == 128);
    REQUIRE(sender.mode() == 0);

    sender.set_key(itb::blob::Slot::Noise, ns.hash_key());
    sender.set_components(itb::blob::Slot::Noise, ns.components());
    sender.set_key(itb::blob::Slot::Data, ds.hash_key());
    sender.set_components(itb::blob::Slot::Data, ds.components());
    sender.set_key(itb::blob::Slot::Start, ss.hash_key());
    sender.set_components(itb::blob::Slot::Start, ss.components());

    auto blob = sender.export_blob(itb::blob::None);
    REQUIRE_FALSE(blob.empty());

    itb::Blob128 receiver{};
    REQUIRE(receiver.mode() == 0);
    receiver.import_blob(blob);
    REQUIRE(receiver.width() == 128);
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

// Triple round-trip — 7 slots: Noise + Data1/2/3 + Start1/2/3.
void triple_roundtrip_via_blob128(const char* primitive,
                                  const std::vector<std::uint8_t>& plaintext) {
    itb::Seed ns {primitive, kKeyBits128};
    itb::Seed d1 {primitive, kKeyBits128};
    itb::Seed d2 {primitive, kKeyBits128};
    itb::Seed d3 {primitive, kKeyBits128};
    itb::Seed s1 {primitive, kKeyBits128};
    itb::Seed s2 {primitive, kKeyBits128};
    itb::Seed s3 {primitive, kKeyBits128};

    auto ct = itb::encrypt_triple(ns, d1, d2, d3, s1, s2, s3, plaintext);

    itb::Blob128 sender{};
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
    REQUIRE_FALSE(blob.empty());

    itb::Blob128 receiver{};
    receiver.import_triple(blob);
    REQUIRE(receiver.width() == 128);
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

TEST_CASE("Blob128 default construct + width + mode fresh-handle invariants",
          "[blob128][lifecycle]") {
    itb::Blob128 b{};
    REQUIRE(b.width() == 128);
    REQUIRE(b.mode() == 0);
    REQUIRE(b.raw_handle() != nullptr);
}

TEST_CASE("Blob128 destructor releases without panic across many constructions",
          "[blob128][lifecycle]") {
    for (int i = 0; i < 16; i++) {
        itb::Blob128 b{};
        REQUIRE(b.width() == 128);
    }
}

TEST_CASE("Blob128 move construction transfers handle ownership",
          "[blob128][lifecycle][move]") {
    itb::Blob128 a{};
    auto* raw = a.raw_handle();
    REQUIRE(raw != nullptr);

    itb::Blob128 b{std::move(a)};
    REQUIRE(b.raw_handle() == raw);
    REQUIRE(b.width() == 128);
    // Source is left in a moved-from state with a nullptr handle —
    // safe to destroy but not to reuse.
}

TEST_CASE("Blob128 move assignment transfers handle and releases the prior one",
          "[blob128][lifecycle][move]") {
    itb::Blob128 a{};
    itb::Blob128 b{};
    auto* raw_a = a.raw_handle();
    REQUIRE(raw_a != nullptr);
    REQUIRE(b.raw_handle() != nullptr);
    REQUIRE(b.raw_handle() != raw_a);

    b = std::move(a);
    REQUIRE(b.raw_handle() == raw_a);
    REQUIRE(b.width() == 128);
}

TEST_CASE("Blob128 self move-assign is a no-op",
          "[blob128][lifecycle][move]") {
    itb::Blob128 a{};
    auto* raw = a.raw_handle();
    // Reference indirection sidesteps GCC's -Wself-move detector while
    // still exercising the operator's `this != &other` guard at runtime.
    itb::Blob128& a_ref = a;
    a = std::move(a_ref);
    REQUIRE(a.raw_handle() == raw);
    REQUIRE(a.width() == 128);
}

// ─── mode() tracking across import_blob / import_triple ────────────

TEST_CASE("Blob128 mode advances 0 → 1 after import_blob, 0 → 3 after import_triple",
          "[blob128][mode]") {
    auto plaintext = token_bytes(64);

    SECTION("import_blob → mode == 1") {
        single_roundtrip_via_blob128("siphash24", plaintext);
    }
    SECTION("import_triple → mode == 3") {
        triple_roundtrip_via_blob128("siphash24", plaintext);
    }
}

// ─── SipHash-2-4 specifics ─────────────────────────────────────────

TEST_CASE("Blob128 siphash24 hash_key is empty (primitive carries no fixed key)",
          "[blob128][siphash24]") {
    itb::Seed s{"siphash24", kKeyBits128};
    REQUIRE(s.hash_key().empty());
    // round-trip via the blob must succeed regardless: from_components
    // accepts an empty hash_key for siphash24.
    auto plaintext = token_bytes(48);
    single_roundtrip_via_blob128("siphash24", plaintext);
}

// ─── Single-mode round-trip × the two 128-bit primitives ──────────

TEST_CASE("Blob128 Single round-trip — siphash24",
          "[blob128][siphash24][single][roundtrip]") {
    auto plaintext = token_bytes(128);
    single_roundtrip_via_blob128("siphash24", plaintext);
}

TEST_CASE("Blob128 Single round-trip — aescmac",
          "[blob128][aescmac][single][roundtrip]") {
    auto plaintext = token_bytes(128);
    // aescmac carries a 16-byte fixed hash key; verify we observe it.
    itb::Seed probe{"aescmac", kKeyBits128};
    REQUIRE(probe.hash_key().size() == 16);
    single_roundtrip_via_blob128("aescmac", plaintext);
}

// ─── Triple-mode round-trip × the two 128-bit primitives ──────────

TEST_CASE("Blob128 Triple round-trip — siphash24",
          "[blob128][siphash24][triple][roundtrip]") {
    auto plaintext = token_bytes(256);
    triple_roundtrip_via_blob128("siphash24", plaintext);
}

TEST_CASE("Blob128 Triple round-trip — aescmac",
          "[blob128][aescmac][triple][roundtrip]") {
    auto plaintext = token_bytes(256);
    triple_roundtrip_via_blob128("aescmac", plaintext);
}

// ─── Varied-payload-size round-trips ──────────────────────────────

TEST_CASE("Blob128 Single round-trip across payload sizes",
          "[blob128][aescmac][single][sizes]") {
    for (std::size_t sz : {std::size_t{32}, std::size_t{4096}, std::size_t{65536}}) {
        SECTION(std::string{"size="} + std::to_string(sz)) {
            single_roundtrip_via_blob128("aescmac", token_bytes(sz));
        }
    }
}
