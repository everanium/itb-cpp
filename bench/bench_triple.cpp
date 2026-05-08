// bench_triple.cpp — Easy Mode Triple-Ouroboros benchmarks for the C++
// binding.
//
// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
// nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (itb::Encryptor::Mixed3 cycling the same BLAKE family +
// Areion-SoEM-256 dedicated lockSeed used by bench_single's mixed
// case) covers the Easy Mode Mixed surface alongside the
// single-primitive grid.
//
// Run with:
//
//   make bench
//   ./bench/build/bench_triple
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
// Areion-SoEM-256 on the dedicated lockSeed slot.
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
// Areion-SoEM-256 lockSeed slot is allocated only when ITB_LOCKSEED is
// set.
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

std::vector<std::unique_ptr<itb::Encryptor>>& encryptor_registry() {
    static std::vector<std::unique_ptr<itb::Encryptor>> reg;
    return reg;
}

itb::Encryptor* register_encryptor(std::unique_ptr<itb::Encryptor> enc) {
    encryptor_registry().push_back(std::move(enc));
    return encryptor_registry().back().get();
}

// ----- Per-case constructors --------------------------------------

bench::BenchCase make_encrypt_case(std::string name, itb::Encryptor* enc) {
    auto payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kPayload));
    bench::BenchFn run = [enc, payload](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            (void)enc->encrypt(payload->data(), payload->size());
        }
    };
    return bench::BenchCase{std::move(name), std::move(run), kPayload};
}

bench::BenchCase make_decrypt_case(std::string name, itb::Encryptor* enc) {
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
                                        itb::Encryptor* enc) {
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
                                        itb::Encryptor* enc) {
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

std::vector<bench::BenchCase> build_cases() {
    std::vector<bench::BenchCase> cases;
    cases.reserve(40);
    for (std::size_t i = 0; i < bench::kPrimitivesCanonicalLen; i++) {
        const char* prim = bench::kPrimitivesCanonical[i];
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_encrypt_16mb", prim, kKeyBits);
        cases.push_back(make_encrypt_case(buf,
            register_encryptor(build_triple(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_decrypt_16mb", prim, kKeyBits);
        cases.push_back(make_decrypt_case(buf,
            register_encryptor(build_triple(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_encrypt_auth_16mb", prim, kKeyBits);
        cases.push_back(make_encrypt_auth_case(buf,
            register_encryptor(build_triple(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_triple_%s_%dbit_decrypt_auth_16mb", prim, kKeyBits);
        cases.push_back(make_decrypt_auth_case(buf,
            register_encryptor(build_triple(prim))));
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "bench_triple_mixed_%dbit_encrypt_16mb", kKeyBits);
    cases.push_back(make_encrypt_case(buf,
        register_encryptor(build_mixed_triple())));
    std::snprintf(buf, sizeof(buf),
                  "bench_triple_mixed_%dbit_decrypt_16mb", kKeyBits);
    cases.push_back(make_decrypt_case(buf,
        register_encryptor(build_mixed_triple())));
    std::snprintf(buf, sizeof(buf),
                  "bench_triple_mixed_%dbit_encrypt_auth_16mb", kKeyBits);
    cases.push_back(make_encrypt_auth_case(buf,
        register_encryptor(build_mixed_triple())));
    std::snprintf(buf, sizeof(buf),
                  "bench_triple_mixed_%dbit_decrypt_auth_16mb", kKeyBits);
    cases.push_back(make_decrypt_auth_case(buf,
        register_encryptor(build_mixed_triple())));
    return cases;
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

        auto cases = build_cases();
        bench::run_all(cases);
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
