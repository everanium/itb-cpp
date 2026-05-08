// test_streams_nonce.cpp — process-wide nonce_bits + streams.
//
// Mutates the process-wide itb::set_nonce_bits atomic to confirm the
// streaming path tracks the active nonce size on every chunk header
// (free-function streams use itb::header_size() under the hood, which
// reads the process-wide value). Catch2 v3 compiles every test_*.cpp
// into its own binary, so this file's process-wide mutations are
// isolated from sibling test binaries by the OS process boundary.
//
// An RAII guard saves and restores the original itb::get_nonce_bits()
// at every TEST_CASE boundary. That keeps each TEST_CASE locally
// hermetic — even when Catch2 is invoked with a filter that runs only
// a subset of the cases here, none of them leak a non-default
// nonce_bits onto a sibling case.
//
// Mirrors bindings/c/tests/test_streams_nonce.c on the C++ surface.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr const char* kPrim = "blake3";
constexpr int         kKb   = 1024;

itb::Seed make_seed() { return itb::Seed{kPrim, kKb}; }

std::vector<std::uint8_t> pseudo_payload(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>(((i * 31u) + 11u) & 0xffu);
    }
    return out;
}

// RAII guard — saves the active process-wide nonce_bits at construction
// and restores it on destruction. Restoration runs even if the test
// throws (catch2's REQUIRE / FAIL), so a mid-test crash cannot leak
// process-wide state into a sibling TEST_CASE.
class NonceBitsGuard {
public:
    NonceBitsGuard() : original_{itb::get_nonce_bits()} {}
    ~NonceBitsGuard() {
        // Best-effort restore; do not propagate exceptions from a dtor.
        try {
            itb::set_nonce_bits(original_);
        } catch (...) {
            // intentionally swallowed
        }
    }
    NonceBitsGuard(const NonceBitsGuard&)            = delete;
    NonceBitsGuard& operator=(const NonceBitsGuard&) = delete;
private:
    int original_;
};

struct VecSource {
    const std::vector<std::uint8_t>* src;
    std::size_t off = 0;
    std::size_t operator()(std::uint8_t* buf, std::size_t cap) {
        std::size_t avail = src->size() - off;
        std::size_t n = (cap < avail) ? cap : avail;
        for (std::size_t i = 0; i < n; ++i) buf[i] = (*src)[off + i];
        off += n;
        return n;
    }
};

constexpr std::size_t kSmallChunk = 4096;

} // namespace

TEST_CASE("process-wide set_nonce_bits round-trips through get_nonce_bits",
          "[streams_nonce][global]") {
    NonceBitsGuard guard;
    const int kCases[] = {128, 256, 512};
    for (int nb : kCases) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            REQUIRE_NOTHROW(itb::set_nonce_bits(nb));
            REQUIRE(itb::get_nonce_bits() == nb);
            REQUIRE(itb::header_size() == nb / 8 + 4);
        }
    }
}

TEST_CASE("StreamEncryptor + StreamDecryptor round-trip across nonce sizes "
          "(single)", "[streams_nonce][single][class]") {
    NonceBitsGuard guard;
    auto pt = pseudo_payload(kSmallChunk * 3 + 100);

    const int kNonces[] = {256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            REQUIRE_NOTHROW(itb::set_nonce_bits(nb));

            auto noise = make_seed();
            auto data  = make_seed();
            auto start = make_seed();

            std::vector<std::uint8_t> ct;
            auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
                ct.insert(ct.end(), p, p + n);
            };
            {
                itb::StreamEncryptor enc{noise, data, start, sink_ct,
                                         kSmallChunk};
                enc.write(pt);
                enc.close();
            }
            REQUIRE(!ct.empty());

            std::vector<std::uint8_t> recovered;
            auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
                recovered.insert(recovered.end(), p, p + n);
            };
            {
                itb::StreamDecryptor dec{noise, data, start, sink_pt};
                dec.feed(ct);
                dec.close();
            }
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("encrypt_stream + decrypt_stream across nonce sizes (single)",
          "[streams_nonce][single][free]") {
    NonceBitsGuard guard;
    auto pt = pseudo_payload(kSmallChunk * 3 + 256);

    const int kNonces[] = {128, 256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            REQUIRE_NOTHROW(itb::set_nonce_bits(nb));

            auto noise = make_seed();
            auto data  = make_seed();
            auto start = make_seed();

            VecSource pt_src{&pt, 0};
            std::vector<std::uint8_t> ct;
            auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
                ct.insert(ct.end(), p, p + n);
            };
            REQUIRE_NOTHROW(itb::encrypt_stream(noise, data, start,
                                                std::ref(pt_src), sink_ct,
                                                kSmallChunk));

            VecSource ct_src{&ct, 0};
            std::vector<std::uint8_t> recovered;
            auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
                recovered.insert(recovered.end(), p, p + n);
            };
            REQUIRE_NOTHROW(itb::decrypt_stream(noise, data, start,
                                                std::ref(ct_src), sink_pt,
                                                kSmallChunk));
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("StreamEncryptorTriple + StreamDecryptorTriple round-trip "
          "across nonce sizes", "[streams_nonce][triple][class]") {
    NonceBitsGuard guard;
    auto pt = pseudo_payload(kSmallChunk * 3);

    const int kNonces[] = {256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            REQUIRE_NOTHROW(itb::set_nonce_bits(nb));

            auto noise = make_seed();
            auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
            auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

            std::vector<std::uint8_t> ct;
            auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
                ct.insert(ct.end(), p, p + n);
            };
            {
                itb::StreamEncryptorTriple enc{noise, d1, d2, d3,
                                               s1, s2, s3,
                                               sink_ct, kSmallChunk};
                enc.write(pt);
                enc.close();
            }
            REQUIRE(!ct.empty());

            std::vector<std::uint8_t> recovered;
            auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
                recovered.insert(recovered.end(), p, p + n);
            };
            {
                itb::StreamDecryptorTriple dec{noise, d1, d2, d3,
                                               s1, s2, s3, sink_pt};
                dec.feed(ct);
                dec.close();
            }
            REQUIRE(recovered == pt);
        }
    }
}

TEST_CASE("encrypt_stream_triple + decrypt_stream_triple across nonce sizes",
          "[streams_nonce][triple][free]") {
    NonceBitsGuard guard;
    auto pt = pseudo_payload(kSmallChunk * 3 + 100);

    const int kNonces[] = {128, 256, 512};
    for (int nb : kNonces) {
        SECTION(std::string{"nonce_bits="} + std::to_string(nb)) {
            REQUIRE_NOTHROW(itb::set_nonce_bits(nb));

            auto noise = make_seed();
            auto d1 = make_seed(); auto d2 = make_seed(); auto d3 = make_seed();
            auto s1 = make_seed(); auto s2 = make_seed(); auto s3 = make_seed();

            VecSource pt_src{&pt, 0};
            std::vector<std::uint8_t> ct;
            auto sink_ct = [&](const std::uint8_t* p, std::size_t n) {
                ct.insert(ct.end(), p, p + n);
            };
            REQUIRE_NOTHROW(itb::encrypt_stream_triple(noise, d1, d2, d3,
                                                       s1, s2, s3,
                                                       std::ref(pt_src),
                                                       sink_ct,
                                                       kSmallChunk));

            VecSource ct_src{&ct, 0};
            std::vector<std::uint8_t> recovered;
            auto sink_pt = [&](const std::uint8_t* p, std::size_t n) {
                recovered.insert(recovered.end(), p, p + n);
            };
            REQUIRE_NOTHROW(itb::decrypt_stream_triple(noise, d1, d2, d3,
                                                       s1, s2, s3,
                                                       std::ref(ct_src),
                                                       sink_pt,
                                                       kSmallChunk));
            REQUIRE(recovered == pt);
        }
    }
}
