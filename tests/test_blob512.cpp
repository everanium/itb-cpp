// test_blob512.cpp — Blob512 width-specific persistence coverage.
//
// Width-typed binary-blob serialisation surface for the two 512-bit
// primitives `blake2b512` and `areion512`. Exercises the Single +
// Triple round-trip path plus byte-level fidelity of the 64-byte
// hash key carried by each primitive at this width, and a
// larger-payload sanity round-trip (~64 KiB) through the cipher.
//
// Process-wide globals (NonceBits / BarrierFill / BitSoup / LockSoup)
// are intentionally not mutated here — those are owned by sibling test
// binaries and would race them inside a shared process.
//
// Mirrors bindings/c/tests/test_blob.c::test_blob_blob512_single_full_matrix
// + test_blob_blob512_triple_full_matrix (with the global-mutation
// scaffolding stripped, since global mutation is forbidden in this
// suite), adapted to Catch2 v3 + the header-only C++ wrappers.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> token_bytes(std::size_t len) {
    static std::uint64_t ctr = 0xB10B512B10B512B0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    std::uint64_t state = ctr;
    std::vector<std::uint8_t> out(len);
    for (std::size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::uint8_t>(state >> 33);
    }
    return out;
}

constexpr int kKeyBits512 = 1024; // multiple of 512

constexpr const char* kPrims512[] = {"blake2b512", "areion512"};

void single_roundtrip(const char* primitive,
                      const std::vector<std::uint8_t>& plaintext) {
    itb::Seed ns{primitive, kKeyBits512};
    itb::Seed ds{primitive, kKeyBits512};
    itb::Seed ss{primitive, kKeyBits512};

    auto ct = itb::encrypt(ns, ds, ss, plaintext);

    itb::Blob512 sender{};
    REQUIRE(sender.width() == 512);
    REQUIRE(sender.mode() == 0);

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
    itb::Seed ns {primitive, kKeyBits512};
    itb::Seed d1 {primitive, kKeyBits512};
    itb::Seed d2 {primitive, kKeyBits512};
    itb::Seed d3 {primitive, kKeyBits512};
    itb::Seed s1 {primitive, kKeyBits512};
    itb::Seed s2 {primitive, kKeyBits512};
    itb::Seed s3 {primitive, kKeyBits512};

    auto ct = itb::encrypt_triple(ns, d1, d2, d3, s1, s2, s3, plaintext);

    itb::Blob512 sender{};
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

    itb::Blob512 receiver{};
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

TEST_CASE("Blob512 fresh-handle invariants",
          "[blob512][lifecycle]") {
    itb::Blob512 b{};
    REQUIRE(b.width() == 512);
    REQUIRE(b.mode() == 0);
    REQUIRE(b.raw_handle() != nullptr);
}

// ─── Single-mode round-trip × the two 512-bit primitives ──────────

TEST_CASE("Blob512 Single round-trip — blake2b512",
          "[blob512][blake2b512][single][roundtrip]") {
    single_roundtrip("blake2b512", token_bytes(512));
}

TEST_CASE("Blob512 Single round-trip — areion512",
          "[blob512][areion512][single][roundtrip]") {
    single_roundtrip("areion512", token_bytes(512));
}

// ─── Triple-mode round-trip × the two 512-bit primitives ──────────

TEST_CASE("Blob512 Triple round-trip — blake2b512",
          "[blob512][blake2b512][triple][roundtrip]") {
    triple_roundtrip("blake2b512", token_bytes(512));
}

TEST_CASE("Blob512 Triple round-trip — areion512",
          "[blob512][areion512][triple][roundtrip]") {
    triple_roundtrip("areion512", token_bytes(512));
}

// ─── 64-byte hash-key fidelity ────────────────────────────────────

TEST_CASE("Blob512 round-trips the 64-byte fixed hash key faithfully",
          "[blob512][hash-key-fidelity]") {
    for (const char* p : kPrims512) {
        SECTION(std::string{"primitive="} + p) {
            itb::Seed s{p, kKeyBits512};
            auto k = s.hash_key();
            REQUIRE(k.size() == 64);

            // Stage into a Blob512 and round-trip through export/import.
            itb::Blob512 sender{};
            sender.set_key(itb::blob::Slot::Noise, k);
            sender.set_components(itb::blob::Slot::Noise, s.components());
            itb::Seed ds{p, kKeyBits512};
            itb::Seed ss{p, kKeyBits512};
            sender.set_key(itb::blob::Slot::Data, ds.hash_key());
            sender.set_components(itb::blob::Slot::Data, ds.components());
            sender.set_key(itb::blob::Slot::Start, ss.hash_key());
            sender.set_components(itb::blob::Slot::Start, ss.components());

            auto blob = sender.export_blob(itb::blob::None);
            itb::Blob512 receiver{};
            receiver.import_blob(blob);
            auto k_back = receiver.get_key(itb::blob::Slot::Noise);
            REQUIRE(k_back.size() == 64);
            REQUIRE(k_back == k);
        }
    }
}

// ─── Larger payload sanity ────────────────────────────────────────

TEST_CASE("Blob512 round-trips a ~64 KiB payload via the 512-bit cipher",
          "[blob512][large-payload]") {
    auto plaintext = token_bytes(65536);
    single_roundtrip("areion512", plaintext);
}
