// bench_single.cpp — Easy Mode Single-Ouroboros benchmarks for the C++
// binding.
//
// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the nine
// PRF-grade primitives, locked at 1024-bit ITB key width and 16 MiB
// CSPRNG-filled payload. One mixed-primitive variant
// (itb::Encryptor::Mixed with BLAKE3 / BLAKE2s / BLAKE2b-256 +
// Areion-SoEM-256 dedicated lockSeed) covers the Easy Mode Mixed
// surface alongside the single-primitive grid.
//
// Run with:
//
//   make bench
//   ./bench/build/bench_single
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
// Areion-SoEM-256 takes the dedicated lockSeed slot — every name
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
// separate calls are issued.
void apply_lockseed_if_requested(itb::Encryptor& enc) {
    if (bench::env_lock_seed()) {
        enc.set_lock_seed(1);
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
// BLAKE2b-256 start). The dedicated Areion-SoEM-256 lockSeed slot is
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

// Heap-resident registry of bench encryptors so each closure can reach
// its Encryptor through a stable pointer. Encryptors are move-only;
// the registry holds owning unique_ptrs.
std::vector<std::unique_ptr<itb::Encryptor>>& encryptor_registry() {
    static std::vector<std::unique_ptr<itb::Encryptor>> reg;
    return reg;
}

itb::Encryptor* register_encryptor(std::unique_ptr<itb::Encryptor> enc) {
    encryptor_registry().push_back(std::move(enc));
    return encryptor_registry().back().get();
}

// ----- Per-case constructors --------------------------------------

// Encryptor + payload constructed once outside the measured loop;
// only the encrypt call is timed.
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

// Pre-encrypts a single ciphertext outside the measured loop; only the
// decrypt call is timed.
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

// Assemble the full case list: 9 single-primitive entries × 4 ops + 1
// mixed entry × 4 ops = 40 cases. Order is primitive-major / op-minor
// so a filter on a primitive name keeps all four ops grouped together
// in the output.
std::vector<bench::BenchCase> build_cases() {
    std::vector<bench::BenchCase> cases;
    cases.reserve(40);
    for (std::size_t i = 0; i < bench::kPrimitivesCanonicalLen; i++) {
        const char* prim = bench::kPrimitivesCanonical[i];
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_encrypt_16mb", prim, kKeyBits);
        cases.push_back(make_encrypt_case(buf,
            register_encryptor(build_single(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_decrypt_16mb", prim, kKeyBits);
        cases.push_back(make_decrypt_case(buf,
            register_encryptor(build_single(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_encrypt_auth_16mb", prim, kKeyBits);
        cases.push_back(make_encrypt_auth_case(buf,
            register_encryptor(build_single(prim))));
        std::snprintf(buf, sizeof(buf),
                      "bench_single_%s_%dbit_decrypt_auth_16mb", prim, kKeyBits);
        cases.push_back(make_decrypt_auth_case(buf,
            register_encryptor(build_single(prim))));
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "bench_single_mixed_%dbit_encrypt_16mb", kKeyBits);
    cases.push_back(make_encrypt_case(buf,
        register_encryptor(build_mixed_single())));
    std::snprintf(buf, sizeof(buf),
                  "bench_single_mixed_%dbit_decrypt_16mb", kKeyBits);
    cases.push_back(make_decrypt_case(buf,
        register_encryptor(build_mixed_single())));
    std::snprintf(buf, sizeof(buf),
                  "bench_single_mixed_%dbit_encrypt_auth_16mb", kKeyBits);
    cases.push_back(make_encrypt_auth_case(buf,
        register_encryptor(build_mixed_single())));
    std::snprintf(buf, sizeof(buf),
                  "bench_single_mixed_%dbit_decrypt_auth_16mb", kKeyBits);
    cases.push_back(make_decrypt_auth_case(buf,
        register_encryptor(build_mixed_single())));
    return cases;
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
