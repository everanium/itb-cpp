// bench_triple_stream.cpp — Triple Ouroboros streaming benchmarks for
// the C++ binding.
//
// Eight cases exercising the full Triple-Ouroboros streaming matrix at
// 64 MiB total payload / 16 MiB chunk size under areion512 + 1024-bit
// ITB key + hmac-blake3 MAC:
//
//     | Mode      | Op      | Variant   |
//     |-----------|---------|-----------|
//     | Easy      | Encrypt | AEAD IO   |
//     | Easy      | Decrypt | AEAD IO   |
//     | Easy      | Encrypt | UserLoop  |
//     | Easy      | Decrypt | UserLoop  |
//     | Low-Level | Encrypt | AEAD IO   |
//     | Low-Level | Decrypt | AEAD IO   |
//     | Low-Level | Encrypt | UserLoop  |
//     | Low-Level | Decrypt | UserLoop  |
//
// AEAD IO  -- Streaming AEAD over caller-supplied StreamSource /
//             StreamSink callbacks. Easy: Encryptor::stream_encrypt_auth
//             / stream_decrypt_auth (mode=3 dispatches Triple
//             internally). Low-Level: itb::encrypt_stream_auth_triple /
//             itb::decrypt_stream_auth_triple free functions over
//             (noise, 3 data, 3 start, mac).
//
// UserLoop -- Plain Streaming via caller-side per-chunk loop; framing
//             convention is a 4-byte big-endian ciphertext-length
//             prefix preceding each chunk's ciphertext bytes. Easy uses
//             Encryptor::encrypt / decrypt; Low-Level uses
//             itb::encrypt_triple / itb::decrypt_triple free functions.
//
// Setup discipline matches bench_single_stream.cpp; see that file's
// header for the construction / measurement contract.
//
// Run with:
//
//   make bench
//   ./bench/build/bench_triple_stream

#include "common.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr const char* kStreamPrimitive = "areion512";
constexpr int         kStreamKeyBits   = 1024;
constexpr const char* kStreamMacName   = "hmac-blake3";
constexpr std::size_t kStreamTotalBytes =
    static_cast<std::size_t>(64) << 20;
constexpr std::size_t kStreamChunkBytes =
    static_cast<std::size_t>(16) << 20;

constexpr std::uint8_t kStreamMacKey[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
};

// ---- Read / write closures over std::vector --------------------------

class MemReader {
public:
    MemReader(const std::uint8_t* p, std::size_t len)
        : buf_{p}, len_{len}, pos_{0} {}

    std::size_t operator()(std::uint8_t* dst, std::size_t cap) {
        std::size_t avail = len_ - pos_;
        std::size_t take = (avail < cap) ? avail : cap;
        if (take > 0) {
            std::memcpy(dst, buf_ + pos_, take);
            pos_ += take;
        }
        return take;
    }

private:
    const std::uint8_t* buf_;
    std::size_t len_;
    std::size_t pos_;
};

class MemWriter {
public:
    explicit MemWriter(std::size_t prealloc) {
        if (prealloc > 0) {
            buf_.reserve(prealloc);
        }
    }

    void operator()(const std::uint8_t* p, std::size_t n) {
        buf_.insert(buf_.end(), p, p + n);
    }

    const std::vector<std::uint8_t>& bytes() const noexcept { return buf_; }
    std::vector<std::uint8_t>&& take() && { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_;
};

inline void frame_chunk(std::vector<std::uint8_t>& w,
                        const std::uint8_t* ct, std::size_t ct_len) {
    std::uint8_t hdr[4];
    hdr[0] = static_cast<std::uint8_t>((ct_len >> 24) & 0xFFu);
    hdr[1] = static_cast<std::uint8_t>((ct_len >> 16) & 0xFFu);
    hdr[2] = static_cast<std::uint8_t>((ct_len >> 8) & 0xFFu);
    hdr[3] = static_cast<std::uint8_t>(ct_len & 0xFFu);
    w.insert(w.end(), hdr, hdr + 4);
    w.insert(w.end(), ct, ct + ct_len);
}

// ---- Construction helpers -------------------------------------------

// mode=3 selects Triple Ouroboros at the Easy Mode constructor.
std::unique_ptr<itb::Encryptor> build_stream_encryptor() {
    auto enc = std::make_unique<itb::Encryptor>(
        kStreamPrimitive, kStreamKeyBits, kStreamMacName, 3);
    if (bench::env_lock_seed()) {
        enc->set_lock_seed(1);
    }
    return enc;
}

// 7-seed Triple kit: noise + 3 data + 3 start, plus the shared MAC.
struct LowLevelKit {
    std::unique_ptr<itb::Seed> noise;
    std::unique_ptr<itb::Seed> data1;
    std::unique_ptr<itb::Seed> data2;
    std::unique_ptr<itb::Seed> data3;
    std::unique_ptr<itb::Seed> start1;
    std::unique_ptr<itb::Seed> start2;
    std::unique_ptr<itb::Seed> start3;
    std::unique_ptr<itb::Mac>  mac;
};

LowLevelKit build_lowlevel_kit() {
    LowLevelKit k;
    k.noise  = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.data1  = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.data2  = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.data3  = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.start1 = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.start2 = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    k.start3 = std::make_unique<itb::Seed>(kStreamPrimitive, kStreamKeyBits);
    std::vector<std::uint8_t> mac_key(kStreamMacKey,
                                      kStreamMacKey + sizeof(kStreamMacKey));
    k.mac    = std::make_unique<itb::Mac>(kStreamMacName, mac_key);
    return k;
}

// ---- Per-case context types -----------------------------------------

struct CaseCtx {
    std::shared_ptr<itb::Encryptor> enc;
    std::shared_ptr<LowLevelKit> kit;
    std::shared_ptr<std::vector<std::uint8_t>> payload;
    std::shared_ptr<std::vector<std::uint8_t>> transcript;
};

std::vector<std::shared_ptr<CaseCtx>>& ctx_registry() {
    static std::vector<std::shared_ptr<CaseCtx>> reg;
    return reg;
}

std::shared_ptr<CaseCtx> register_ctx() {
    auto c = std::make_shared<CaseCtx>();
    ctx_registry().push_back(c);
    return c;
}

// ---- Per-iter callables: Easy AEAD IO -------------------------------

bench::BenchFn make_run_easy_encrypt_aead_io(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            MemReader reader(c->payload->data(), c->payload->size());
            MemWriter writer(kStreamTotalBytes + (kStreamTotalBytes >> 3));
            c->enc->stream_encrypt_auth(
                std::ref(reader), std::ref(writer), kStreamChunkBytes);
        }
    };
}

bench::BenchFn make_run_easy_decrypt_aead_io(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            MemReader reader(c->transcript->data(), c->transcript->size());
            MemWriter writer(kStreamTotalBytes);
            c->enc->stream_decrypt_auth(
                std::ref(reader), std::ref(writer), kStreamChunkBytes);
        }
    };
}

// ---- Per-iter callables: Easy UserLoop -------------------------------

bench::BenchFn make_run_easy_encrypt_userloop(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            std::vector<std::uint8_t> w;
            w.reserve(kStreamTotalBytes + (kStreamTotalBytes >> 3));
            std::size_t off = 0;
            while (off < c->payload->size()) {
                std::size_t end = off + kStreamChunkBytes;
                if (end > c->payload->size()) end = c->payload->size();
                auto ct = c->enc->encrypt(c->payload->data() + off, end - off);
                frame_chunk(w, ct.data(), ct.size());
                off = end;
            }
        }
    };
}

bench::BenchFn make_run_easy_decrypt_userloop(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            std::vector<std::uint8_t> w;
            w.reserve(kStreamTotalBytes);
            std::size_t off = 0;
            const auto& tr = *c->transcript;
            while (off + 4 <= tr.size()) {
                std::size_t ct_len =
                    (static_cast<std::size_t>(tr[off]) << 24) |
                    (static_cast<std::size_t>(tr[off + 1]) << 16) |
                    (static_cast<std::size_t>(tr[off + 2]) << 8) |
                    (static_cast<std::size_t>(tr[off + 3]));
                off += 4;
                if (off + ct_len > tr.size()) {
                    std::fprintf(stderr,
                                 "easy decrypt userloop: truncated transcript\n");
                    std::abort();
                }
                auto pt = c->enc->decrypt(tr.data() + off, ct_len);
                w.insert(w.end(), pt.begin(), pt.end());
                off += ct_len;
            }
        }
    };
}

// ---- Per-iter callables: Low-Level AEAD IO ---------------------------

bench::BenchFn make_run_lowlevel_encrypt_aead_io(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            MemReader reader(c->payload->data(), c->payload->size());
            MemWriter writer(kStreamTotalBytes + (kStreamTotalBytes >> 3));
            itb::encrypt_stream_auth_triple(
                *c->kit->noise,
                *c->kit->data1, *c->kit->data2, *c->kit->data3,
                *c->kit->start1, *c->kit->start2, *c->kit->start3,
                *c->kit->mac,
                std::ref(reader), std::ref(writer), kStreamChunkBytes);
        }
    };
}

bench::BenchFn make_run_lowlevel_decrypt_aead_io(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            MemReader reader(c->transcript->data(), c->transcript->size());
            MemWriter writer(kStreamTotalBytes);
            itb::decrypt_stream_auth_triple(
                *c->kit->noise,
                *c->kit->data1, *c->kit->data2, *c->kit->data3,
                *c->kit->start1, *c->kit->start2, *c->kit->start3,
                *c->kit->mac,
                std::ref(reader), std::ref(writer), kStreamChunkBytes);
        }
    };
}

// ---- Per-iter callables: Low-Level UserLoop --------------------------

bench::BenchFn make_run_lowlevel_encrypt_userloop(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            std::vector<std::uint8_t> w;
            w.reserve(kStreamTotalBytes + (kStreamTotalBytes >> 3));
            std::size_t off = 0;
            while (off < c->payload->size()) {
                std::size_t end = off + kStreamChunkBytes;
                if (end > c->payload->size()) end = c->payload->size();
                auto ct = itb::encrypt_triple(
                    *c->kit->noise,
                    *c->kit->data1, *c->kit->data2, *c->kit->data3,
                    *c->kit->start1, *c->kit->start2, *c->kit->start3,
                    c->payload->data() + off, end - off);
                frame_chunk(w, ct.data(), ct.size());
                off = end;
            }
        }
    };
}

bench::BenchFn make_run_lowlevel_decrypt_userloop(std::shared_ptr<CaseCtx> c) {
    return [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; i++) {
            std::vector<std::uint8_t> w;
            w.reserve(kStreamTotalBytes);
            std::size_t off = 0;
            const auto& tr = *c->transcript;
            while (off + 4 <= tr.size()) {
                std::size_t ct_len =
                    (static_cast<std::size_t>(tr[off]) << 24) |
                    (static_cast<std::size_t>(tr[off + 1]) << 16) |
                    (static_cast<std::size_t>(tr[off + 2]) << 8) |
                    (static_cast<std::size_t>(tr[off + 3]));
                off += 4;
                if (off + ct_len > tr.size()) {
                    std::fprintf(stderr,
                                 "low-level decrypt userloop: truncated transcript\n");
                    std::abort();
                }
                auto pt = itb::decrypt_triple(
                    *c->kit->noise,
                    *c->kit->data1, *c->kit->data2, *c->kit->data3,
                    *c->kit->start1, *c->kit->start2, *c->kit->start3,
                    tr.data() + off, ct_len);
                w.insert(w.end(), pt.begin(), pt.end());
                off += ct_len;
            }
        }
    };
}

// ---- Pre-encryption helpers (decrypt-side setup) --------------------

std::vector<std::uint8_t> prebuild_easy_aead_transcript(
    itb::Encryptor& enc, const std::vector<std::uint8_t>& payload) {
    MemReader reader(payload.data(), payload.size());
    MemWriter writer(kStreamTotalBytes + (kStreamTotalBytes >> 3));
    enc.stream_encrypt_auth(
        std::ref(reader), std::ref(writer), kStreamChunkBytes);
    return std::move(writer).take();
}

std::vector<std::uint8_t> prebuild_lowlevel_aead_transcript(
    const LowLevelKit& kit, const std::vector<std::uint8_t>& payload) {
    MemReader reader(payload.data(), payload.size());
    MemWriter writer(kStreamTotalBytes + (kStreamTotalBytes >> 3));
    itb::encrypt_stream_auth_triple(
        *kit.noise,
        *kit.data1, *kit.data2, *kit.data3,
        *kit.start1, *kit.start2, *kit.start3,
        *kit.mac,
        std::ref(reader), std::ref(writer), kStreamChunkBytes);
    return std::move(writer).take();
}

std::vector<std::uint8_t> prebuild_easy_userloop_transcript(
    itb::Encryptor& enc, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> w;
    w.reserve(kStreamTotalBytes + (kStreamTotalBytes >> 3));
    std::size_t off = 0;
    while (off < payload.size()) {
        std::size_t end = off + kStreamChunkBytes;
        if (end > payload.size()) end = payload.size();
        auto ct = enc.encrypt(payload.data() + off, end - off);
        frame_chunk(w, ct.data(), ct.size());
        off = end;
    }
    return w;
}

std::vector<std::uint8_t> prebuild_lowlevel_userloop_transcript(
    const LowLevelKit& kit, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> w;
    w.reserve(kStreamTotalBytes + (kStreamTotalBytes >> 3));
    std::size_t off = 0;
    while (off < payload.size()) {
        std::size_t end = off + kStreamChunkBytes;
        if (end > payload.size()) end = payload.size();
        auto ct = itb::encrypt_triple(
            *kit.noise,
            *kit.data1, *kit.data2, *kit.data3,
            *kit.start1, *kit.start2, *kit.start3,
            payload.data() + off, end - off);
        frame_chunk(w, ct.data(), ct.size());
        off = end;
    }
    return w;
}

// ---- Case constructors ----------------------------------------------

bench::BenchCase make_easy_encrypt_aead_io(std::string name) {
    auto c = register_ctx();
    c->enc = build_stream_encryptor();
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    return bench::BenchCase{std::move(name),
                            make_run_easy_encrypt_aead_io(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_easy_decrypt_aead_io(std::string name) {
    auto c = register_ctx();
    c->enc = build_stream_encryptor();
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    c->transcript = std::make_shared<std::vector<std::uint8_t>>(
        prebuild_easy_aead_transcript(*c->enc, *c->payload));
    return bench::BenchCase{std::move(name),
                            make_run_easy_decrypt_aead_io(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_easy_encrypt_userloop(std::string name) {
    auto c = register_ctx();
    c->enc = build_stream_encryptor();
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    return bench::BenchCase{std::move(name),
                            make_run_easy_encrypt_userloop(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_easy_decrypt_userloop(std::string name) {
    auto c = register_ctx();
    c->enc = build_stream_encryptor();
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    c->transcript = std::make_shared<std::vector<std::uint8_t>>(
        prebuild_easy_userloop_transcript(*c->enc, *c->payload));
    return bench::BenchCase{std::move(name),
                            make_run_easy_decrypt_userloop(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_lowlevel_encrypt_aead_io(std::string name) {
    auto c = register_ctx();
    c->kit = std::make_shared<LowLevelKit>(build_lowlevel_kit());
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    return bench::BenchCase{std::move(name),
                            make_run_lowlevel_encrypt_aead_io(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_lowlevel_decrypt_aead_io(std::string name) {
    auto c = register_ctx();
    c->kit = std::make_shared<LowLevelKit>(build_lowlevel_kit());
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    c->transcript = std::make_shared<std::vector<std::uint8_t>>(
        prebuild_lowlevel_aead_transcript(*c->kit, *c->payload));
    return bench::BenchCase{std::move(name),
                            make_run_lowlevel_decrypt_aead_io(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_lowlevel_encrypt_userloop(std::string name) {
    auto c = register_ctx();
    c->kit = std::make_shared<LowLevelKit>(build_lowlevel_kit());
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    return bench::BenchCase{std::move(name),
                            make_run_lowlevel_encrypt_userloop(c),
                            kStreamTotalBytes};
}

bench::BenchCase make_lowlevel_decrypt_userloop(std::string name) {
    auto c = register_ctx();
    c->kit = std::make_shared<LowLevelKit>(build_lowlevel_kit());
    c->payload = std::make_shared<std::vector<std::uint8_t>>(
        bench::random_bytes_vec(kStreamTotalBytes));
    c->transcript = std::make_shared<std::vector<std::uint8_t>>(
        prebuild_lowlevel_userloop_transcript(*c->kit, *c->payload));
    return bench::BenchCase{std::move(name),
                            make_run_lowlevel_decrypt_userloop(c),
                            kStreamTotalBytes};
}

// ---- Case-list assembly --------------------------------------------

constexpr const char* kNamePrefix =
    "bench_triple_stream_areion512_1024bit_64mb";

std::vector<bench::BenchCase> build_cases() {
    std::vector<bench::BenchCase> cases;
    cases.reserve(8);
    char buf[160];

    std::snprintf(buf, sizeof(buf), "%s_easy_encrypt_aead_io", kNamePrefix);
    cases.push_back(make_easy_encrypt_aead_io(buf));
    std::snprintf(buf, sizeof(buf), "%s_easy_decrypt_aead_io", kNamePrefix);
    cases.push_back(make_easy_decrypt_aead_io(buf));
    std::snprintf(buf, sizeof(buf), "%s_easy_encrypt_userloop", kNamePrefix);
    cases.push_back(make_easy_encrypt_userloop(buf));
    std::snprintf(buf, sizeof(buf), "%s_easy_decrypt_userloop", kNamePrefix);
    cases.push_back(make_easy_decrypt_userloop(buf));
    std::snprintf(buf, sizeof(buf), "%s_lowlevel_encrypt_aead_io", kNamePrefix);
    cases.push_back(make_lowlevel_encrypt_aead_io(buf));
    std::snprintf(buf, sizeof(buf), "%s_lowlevel_decrypt_aead_io", kNamePrefix);
    cases.push_back(make_lowlevel_decrypt_aead_io(buf));
    std::snprintf(buf, sizeof(buf), "%s_lowlevel_encrypt_userloop", kNamePrefix);
    cases.push_back(make_lowlevel_encrypt_userloop(buf));
    std::snprintf(buf, sizeof(buf), "%s_lowlevel_decrypt_userloop", kNamePrefix);
    cases.push_back(make_lowlevel_decrypt_userloop(buf));

    return cases;
}

} // namespace

int main() {
    try {
        int nonce_bits = bench::env_nonce_bits(128);
        itb::set_max_workers(0);
        itb::set_nonce_bits(nonce_bits);

        std::printf("# triple_stream payload_bytes=%zu chunk_bytes=%zu "
                    "primitive=%s key_bits=%d mac=%s nonce_bits=%d "
                    "lockseed=%s workers=auto\n",
                    kStreamTotalBytes, kStreamChunkBytes, kStreamPrimitive,
                    kStreamKeyBits, kStreamMacName, nonce_bits,
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
