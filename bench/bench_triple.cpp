// bench_triple.cpp — Easy Mode Triple-Ouroboros benchmarks for the C++
// binding.
//
// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for
// PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (itb::Encryptor::Mixed3 + dedicated lockSeed) covers the
// Easy Mode Mixed surface alongside the single-primitive grid.
//
// Run with:
//
//   make bench
//   ./bench/build/bench_triple
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./bench/build/bench_triple
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/build/bench_triple
//
//   ITB_BENCH_FILTER=blake3_encrypt ./bench/build/bench_triple
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

namespace {

// Mixed-primitive composition for Triple Ouroboros — the same four
// 256-bit-wide names used by bench_single's Mixed case are cycled
// across the seven seed slots (noise + 3 data + 3 start) plus
// one on the dedicated lockSeed slot.
constexpr const char* kMixedNoise  = "blake3";
constexpr const char* kMixedData1  = "blake2s";
constexpr const char* kMixedData2  = "blake2b256";
constexpr const char* kMixedData3  = "blake3";
constexpr const char* kMixedStart1 = "blake2s";
constexpr const char* kMixedStart2 = "blake2b256";
constexpr const char* kMixedStart3 = "blake3";
constexpr const char* kMixedLock   = "areion256";

constexpr int         kKeyBits   = 1024;
constexpr const char* kMacName   = "hmac-blake3";
constexpr std::size_t kPayload   = bench::kPayload16MB;

void apply_lockseed_if_requested(itb::Encryptor& enc) {
    if (bench::env_lock_seed()) {
        enc.set_lock_seed(1);
    }
    // When ITB_LOCKBATCH is also set, enable the Lock Batch performance
    // Lock Soup mode on the same encryptor.
    if (bench::env_lock_batch()) {
        enc.set_lock_batch(1);
    }
}

// Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
// with HMAC-BLAKE3 authentication. Triple = mode=3, 7-seed layout.
std::unique_ptr<itb::Encryptor> build_triple(const char* primitive) {
    auto enc = std::make_unique<itb::Encryptor>(primitive, kKeyBits,
                                                kMacName, 3);
    apply_lockseed_if_requested(*enc);
    return enc;
}

// Construct a mixed-primitive Triple-Ouroboros encryptor with the
// four-name BLAKE family across the seven middle slots. The dedicated
// lockSeed slot is allocated only when ITB_LOCKSEED is set.
std::unique_ptr<itb::Encryptor> build_mixed_triple() {
    std::string_view prim_l = bench::env_lock_seed()
                                  ? std::string_view{kMixedLock}
                                  : std::string_view{};
    auto enc = std::make_unique<itb::Encryptor>(itb::Encryptor::Mixed3(
        kMixedNoise,
        kMixedData1, kMixedData2, kMixedData3,
        kMixedStart1, kMixedStart2, kMixedStart3,
        prim_l,
        kKeyBits, kMacName));
    return enc;
}

// ----- Per-case constructors (factory-friendly, each builds own Encryptor)

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

using CaseFactory = std::function<bench::BenchCase()>;
struct NamedFactory {
    std::string  name;
    CaseFactory  factory;
};

std::vector<NamedFactory> build_lazy_factories() {
    std::vector<NamedFactory> facs;
    facs.reserve(40);

    for (std::size_t i = 0; i < bench::kPrimitivesCanonicalLen; i++) {
        std::string prim(bench::kPrimitivesCanonical[i]);
        char buf[128];

        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_encrypt_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_encrypt_case(
            std::string("bench_triple_") + prim + "_" + std::to_string(kKeyBits) + "bit_encrypt_16mb",
            build_triple(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_decrypt_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_decrypt_case(
            std::string("bench_triple_") + prim + "_" + std::to_string(kKeyBits) + "bit_decrypt_16mb",
            build_triple(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_encrypt_auth_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_encrypt_auth_case(
            std::string("bench_triple_") + prim + "_" + std::to_string(kKeyBits) + "bit_encrypt_auth_16mb",
            build_triple(prim.c_str())); }});

        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_decrypt_auth_16mb", prim.c_str(), kKeyBits);
        facs.push_back({buf, [prim]{ return make_decrypt_auth_case(
            std::string("bench_triple_") + prim + "_" + std::to_string(kKeyBits) + "bit_decrypt_auth_16mb",
            build_triple(prim.c_str())); }});
    }

    std::string en  = std::string("bench_triple_mixed_") + std::to_string(kKeyBits) + "bit_encrypt_16mb";
    std::string dn  = std::string("bench_triple_mixed_") + std::to_string(kKeyBits) + "bit_decrypt_16mb";
    std::string ean = std::string("bench_triple_mixed_") + std::to_string(kKeyBits) + "bit_encrypt_auth_16mb";
    std::string dan = std::string("bench_triple_mixed_") + std::to_string(kKeyBits) + "bit_decrypt_auth_16mb";
    facs.push_back({en,  [en]  { return make_encrypt_case(en,  build_mixed_triple()); }});
    facs.push_back({dn,  [dn]  { return make_decrypt_case(dn,  build_mixed_triple()); }});
    facs.push_back({ean, [ean] { return make_encrypt_auth_case(ean, build_mixed_triple()); }});
    facs.push_back({dan, [dan] { return make_decrypt_auth_case(dan, build_mixed_triple()); }});

    return facs;
}

} // namespace

int main() {
    try {
        int nonce_bits = bench::env_nonce_bits(128);
        itb::set_max_workers(0);
        itb::set_nonce_bits(nonce_bits);

        std::printf("# easy_triple primitives=%zu key_bits=%d mac=%s "
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
