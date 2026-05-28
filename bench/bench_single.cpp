// bench_single.cpp — Easy Mode Single-Ouroboros benchmarks for the C++
// binding.
//
// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for
// PRF-grade primitives, locked at 1024-bit ITB key width and 16 MiB
// CSPRNG-filled payload. One mixed-primitive variant
// (itb::Encryptor::Mixed + dedicated lockSeed) covers
// the Easy Mode Mixed surface alongside the single-primitive grid.
//
// Run with:
//
//   make bench
//   ./bench/build/bench_single
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./bench/build/bench_single
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/build/bench_single
//
//   ITB_BENCH_FILTER=blake3_encrypt ./bench/build/bench_single
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s). See common.hpp for the supported environment variables
// and the convergence policy.

#include "common.hpp"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// Mixed-primitive composition used by the bench_single_mixed_* cases.
// noise / data / start cycle through the BLAKE family while
// Areion takes the dedicated lockSeed slot — every name
// resolves to a 256-bit native hash width so the Mixed factory's
// width-check passes.
namespace {

constexpr const char* kMixedNoise = "blake3";
constexpr const char* kMixedData  = "blake2s";
constexpr const char* kMixedStart = "blake2b256";
constexpr const char* kMixedLock  = "areion256";

constexpr int         kKeyBits   = 1024;
constexpr const char* kMacName   = "hmac-blake3";
constexpr std::size_t kPayload   = bench::kPayload16MB;

// Apply the dedicated lockSeed slot when ITB_LOCKSEED is set. Easy
// Mode auto-couples BitSoup + LockSoup as a side effect, so no
// separate calls are issued. When ITB_LOCKBATCH is also set, enable the
// Lock Batch performance Lock Soup mode on the same encryptor.
void apply_lockseed_if_requested(itb::Encryptor& enc) {
    if (bench::env_lock_seed()) {
        enc.set_lock_seed(1);
    }
    if (bench::env_lock_batch()) {
        enc.set_lock_batch(1);
    }
}

// Construct a single-primitive 1024-bit Single-Ouroboros encryptor with
// HMAC-BLAKE3 authentication. Heap-allocated so the closure can capture
// a stable pointer; the registry below owns lifetime.
std::unique_ptr<itb::Encryptor> build_single(const char* primitive) {
    auto enc = std::make_unique<itb::Encryptor>(primitive, kKeyBits,
                                                kMacName, 1);
    apply_lockseed_if_requested(*enc);
    return enc;
}

// Construct a mixed-primitive Single-Ouroboros encryptor matching the
// README Quick Start composition (BLAKE3 noise / BLAKE2s data /
// BLAKE2b-256 start). The dedicated lockSeed slot is
// allocated only when ITB_LOCKSEED is set, so the no-LockSeed bench
// arm measures the plain mixed-primitive cost without the BitSoup +
// LockSoup auto-couple. The four primitive names share the 256-bit
// native hash width.
std::unique_ptr<itb::Encryptor> build_mixed_single() {
    // When `prim_l` is non-empty, Mixed auto-couples BitSoup +
    // LockSoup on construction. When `prim_l` is empty the encryptor
    // stays in plain mixed mode.
    std::string_view prim_l = bench::env_lock_seed()
                                  ? std::string_view{kMixedLock}
                                  : std::string_view{};
    auto enc = std::make_unique<itb::Encryptor>(itb::Encryptor::Mixed(
        kMixedNoise, kMixedData, kMixedStart, prim_l,
        kKeyBits, kMacName));
    return enc;
}

// ----- Per-case constructors (factory-friendly, each builds own Encryptor)

// Each make_*_case creates a fresh Encryptor via shared_ptr so the
// BenchCase closure owns it; when the BenchCase is destroyed the
// Encryptor is released immediately.

bench::BenchCase make_encrypt_case(std::string name,
                                   std::unique_ptr<itb::Encryptor> enc_owner) {
    auto enc = std::shared_ptr<itb::Encryptor>(std::move(enc_owner));
    auto payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kPayload));
    bench::BenchFn run = [enc, payload](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            (void)enc->encrypt(payload->data(), payload->size());
        }
    };
    return bench::BenchCase{std::move(name), std::move(run), kPayload};
}

bench::BenchCase make_decrypt_case(std::string name,
                                   std::unique_ptr<itb::Encryptor> enc_owner) {
    auto enc = std::shared_ptr<itb::Encryptor>(std::move(enc_owner));
    auto payload = bench::random_bytes_vec(kPayload);
    auto ciphertext = std::make_shared<std::vector<std::uint8_t>>(
        enc->encrypt(payload.data(), payload.size()));
    bench::BenchFn run = [enc, ciphertext](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            (void)enc->decrypt(ciphertext->data(), ciphertext->size());
        }
    };
    return bench::BenchCase{std::move(name), std::move(run), kPayload};
}

bench::BenchCase make_encrypt_auth_case(std::string name,
                                        std::unique_ptr<itb::Encryptor> enc_owner) {
    auto enc = std::shared_ptr<itb::Encryptor>(std::move(enc_owner));
    auto payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kPayload));
    bench::BenchFn run = [enc, payload](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            (void)enc->encrypt_auth(payload->data(), payload->size());
        }
    };
    return bench::BenchCase{std::move(name), std::move(run), kPayload};
}

bench::BenchCase make_decrypt_auth_case(std::string name,
                                        std::unique_ptr<itb::Encryptor> enc_owner) {
    auto enc = std::shared_ptr<itb::Encryptor>(std::move(enc_owner));
    auto payload = bench::random_bytes_vec(kPayload);
    auto ciphertext = std::make_shared<std::vector<std::uint8_t>>(
        enc->encrypt_auth(payload.data(), payload.size()));
    bench::BenchFn run = [enc, ciphertext](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            (void)enc->decrypt_auth(ciphertext->data(), ciphertext->size());
        }
    };
    return bench::BenchCase{std::move(name), std::move(run), kPayload};
}

// Lazy factory type: builds one BenchCase on demand.
using CaseFactory = std::function<bench::BenchCase()>;
struct NamedFactory {
    std::string  name;
    CaseFactory  factory;
};

// Return a list of cheap NamedFactory pairs for the full 40-case message
// suite. No payload or Encryptor is allocated here.
std::vector<NamedFactory> build_lazy_factories() {
    std::vector<NamedFactory> facs;
    facs.reserve(40);

    for (std::size_t i = 0; i < bench::kPrimitivesCanonicalLen; i++) {
        std::string prim(bench::kPrimitivesCanonical[i]);
        char buf[128];

        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_encrypt_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_encrypt_case(
            std::string("bench_single_") + prim + "_" + std::to_string(kKeyBits) + "bit_encrypt_16mb",
            build_single(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_decrypt_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_decrypt_case(
            std::string("bench_single_") + prim + "_" + std::to_string(kKeyBits) + "bit_decrypt_16mb",
            build_single(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_encrypt_auth_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_encrypt_auth_case(
            std::string("bench_single_") + prim + "_" + std::to_string(kKeyBits) + "bit_encrypt_auth_16mb",
            build_single(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_decrypt_auth_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_decrypt_auth_case(
            std::string("bench_single_") + prim + "_" + std::to_string(kKeyBits) + "bit_decrypt_auth_16mb",
            build_single(prim.c_str())); }});
    }

    // Mixed entries.
    std::string en  = std::string("bench_single_mixed_") + std::to_string(kKeyBits) + "bit_encrypt_16mb";
    std::string dn  = std::string("bench_single_mixed_") + std::to_string(kKeyBits) + "bit_decrypt_16mb";
    std::string ean = std::string("bench_single_mixed_") + std::to_string(kKeyBits) + "bit_encrypt_auth_16mb";
    std::string dan = std::string("bench_single_mixed_") + std::to_string(kKeyBits) + "bit_decrypt_auth_16mb";
    facs.push_back({en,  [en]  { return make_encrypt_case(en,  build_mixed_single()); }});
    facs.push_back({dn,  [dn]  { return make_decrypt_case(dn,  build_mixed_single()); }});
    facs.push_back({ean, [ean] { return make_encrypt_auth_case(ean, build_mixed_single()); }});
    facs.push_back({dan, [dan] { return make_decrypt_auth_case(dan, build_mixed_single()); }});

    return facs;
}

} // namespace

int main() {
    try {
        int nonce_bits = bench::env_nonce_bits(128);
        itb::set_max_workers(0);
        itb::set_nonce_bits(nonce_bits);

        std::printf("# easy_single primitives=%zu key_bits=%d mac=%s "
                    "nonce_bits=%d lockseed=%s workers=auto\n",
                    bench::kPrimitivesCanonicalLen,
                    kKeyBits,
                    kMacName,
                    nonce_bits,
                    bench::env_lock_seed() ? "on" : "off");
        std::fflush(stdout);

        auto facs = build_lazy_factories();
        const char* flt = bench::env_filter();
        double min_seconds = bench::env_min_seconds();

        std::vector<const NamedFactory*> selected;
        for (const auto& nf : facs) {
            if (flt == nullptr || nf.name.find(flt) != std::string::npos) {
                selected.push_back(&nf);
            }
        }

        if (selected.empty()) {
            std::fprintf(stderr,
                         "no bench cases match filter %s; available:",
                         flt == nullptr ? "<unset>" : flt);
            for (const auto& nf : facs) {
                std::fprintf(stderr, " %s", nf.name.c_str());
            }
            std::fprintf(stderr, "\n");
            return 0;
        }

        std::printf("# benchmarks=%zu payload_bytes=%zu min_seconds=%g\n",
                    selected.size(), kPayload, min_seconds);
        std::fflush(stdout);

        for (const auto* nf : selected) {
            auto c = nf->factory();
            bench::measure_one(c, min_seconds);
        }
    } catch (const itb::ItbError& e) {
        std::fprintf(stderr, "itb error (code=%d): %s\n",
                     e.code(), e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench failed: %s\n", e.what());
        return 1;
    }
    return 0;
}
