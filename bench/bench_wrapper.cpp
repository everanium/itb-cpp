// bench_wrapper.cpp — format-deniability wrapper benchmarks for the
// C++ binding.
//
// Mirrors `wrapper/bench_test.go` from the root repository, adapted
// for the C++ binding asymmetry: the Streaming No MAC arm covers only
// the User-Driven Loop variant (the C++ binding does not expose a
// `std::ostream` / `std::istream` wrapper writer / reader pair for
// Non-AEAD streaming).
//
// Total sub-bench count: **102**.
//
//   - Wrapper Only round-trip (16 MiB blob)              :  6
//     ( 3 ciphers × 2 variants {Wrap, WrapInPlace} )
//   - Message Single — 4 modes × 3 ciphers × 2 dirs      : 24
//   - Message Triple — 4 modes × 3 ciphers × 2 dirs      : 24
//   - Streaming Single — 4 modes × 3 ciphers × 2 dirs    : 24
//   - Streaming Triple — 4 modes × 3 ciphers × 2 dirs    : 24
//
// 4 message modes: easy-nomac / easy-auth / lowlevel-nomac /
// lowlevel-auth.
//
// 4 streaming modes: aead-easy-io / aead-lowlevel-io /
// noaead-easy-userloop / noaead-lowlevel-userloop.
//
// Both encrypt and decrypt are timed separately. Decrypt benches
// refresh the working wire from a pristine copy each iteration —
// the memcpy is included in the timed total, matching the
// cross-binding convention.
//
// Run with:
//
//     make bench
//     ./bench/build/bench_wrapper
//
//     ITB_BENCH_FILTER=BenchmarkWrapperOnly ./bench/build/bench_wrapper
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s).

#include "common.hpp"

#include <itb.hpp>
#include <itb/wrapper.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

// ----- Configuration ------------------------------------------------

constexpr itb::wrapper::Cipher kCiphers[] = {
    itb::wrapper::Cipher::Aes128Ctr,
    itb::wrapper::Cipher::ChaCha20,
    itb::wrapper::Cipher::SipHash24,
};
constexpr const char* kCipherNames[] = { "aes", "chacha", "siphash" };
constexpr std::size_t kCipherCount = 3;

constexpr std::size_t kWrapperPayloadBytes = bench::kPayload16MB;
constexpr std::size_t kMessagePayloadBytes = bench::kPayload16MB;
constexpr std::size_t kStreamPayloadBytes  = static_cast<std::size_t>(64) << 20;
constexpr std::size_t kStreamChunkBytes    = static_cast<std::size_t>(16) << 20;

constexpr const char* kBenchPrimitive = "areion512";
constexpr int         kBenchKeyBits   = 1024;
constexpr const char* kBenchMacName   = "hmac-blake3";

// ----- Encryptor factory --------------------------------------------

std::unique_ptr<itb::Encryptor> new_encryptor(int mode, bool with_mac) {
    auto enc = std::make_unique<itb::Encryptor>(
        kBenchPrimitive, kBenchKeyBits,
        with_mac ? kBenchMacName : "",
        mode);
    // Match the wrapper/bench_test.go config: minimal config so the
    // outer cipher delta is not masked by per-pixel feature cost.
    enc->set_nonce_bits(128);
    enc->set_barrier_fill(1);
    enc->set_bit_soup(0);
    enc->set_lock_soup(0);
    return enc;
}

// ----- Owning context registry --------------------------------------
//
// Bench cases capture pointers into stable storage so the closures
// can read pre-built encryptors / payloads / pristine wires across
// every measured iteration. The registry below owns the lifetime of
// every per-case context; each `BenchCase::run` is a closure that
// captures a raw pointer into the registry.
//
// `std::unique_ptr<...>` storage is fine because the registry vector
// is appended to but never reordered after the BenchCase is built.

struct CaseCtx {
    std::unique_ptr<itb::Encryptor> enc;
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> outer_key;
    std::vector<std::uint8_t> pristine_wire;
    std::vector<std::uint8_t> work_wire;
    itb::wrapper::Cipher cipher{itb::wrapper::Cipher::Aes128Ctr};
    int  mode{1};
    bool auth{false};
};

std::vector<std::unique_ptr<CaseCtx>>& ctx_registry() {
    static std::vector<std::unique_ptr<CaseCtx>> reg;
    return reg;
}

CaseCtx* register_ctx(std::unique_ptr<CaseCtx> ctx) {
    ctx_registry().push_back(std::move(ctx));
    return ctx_registry().back().get();
}

// ----- Wrapper Only sub-benches -------------------------------------
//
// Pure outer cipher cost — no ITB call. Two variants per cipher:
// Wrap (alloc) and WrapInPlace (zero alloc).
//
// Each iter performs one wrap + one unwrap (encrypt + decrypt timed
// together, mirroring the Go BenchmarkWrapperOnlyWrap / InPlace
// cases). Payload is 16 MiB pseudo-random bytes.

bench::BenchCase make_wrapper_only_wrap_case(itb::wrapper::Cipher cipher,
                                             const char* cipher_name) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->cipher = cipher;
    ctx->payload = bench::random_bytes_vec(kWrapperPayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkWrapperOnlyWrap/%s", cipher_name);
    bench::BenchFn run = [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; ++i) {
            auto wire = itb::wrapper::wrap(c->cipher,
                                           c->outer_key.data(), c->outer_key.size(),
                                           c->payload.data(), c->payload.size());
            auto recovered = itb::wrapper::unwrap(c->cipher,
                                                  c->outer_key.data(), c->outer_key.size(),
                                                  wire.data(), wire.size());
            (void)recovered;
        }
    };
    return bench::BenchCase{namebuf, std::move(run), kWrapperPayloadBytes};
}

bench::BenchCase make_wrapper_only_inplace_case(itb::wrapper::Cipher cipher,
                                                const char* cipher_name) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->cipher = cipher;
    ctx->payload = bench::random_bytes_vec(kWrapperPayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);
    std::size_t nlen = itb::wrapper::nonce_size(cipher);
    ctx->work_wire.resize(nlen + kWrapperPayloadBytes);
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkWrapperOnlyInPlace/%s", cipher_name);
    bench::BenchFn run = [c, nlen](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; ++i) {
            // Refresh body from pristine payload so each iter does
            // identical work.
            std::memcpy(c->work_wire.data() + nlen,
                        c->payload.data(),
                        c->payload.size());
            auto nonce = itb::wrapper::wrap_in_place(
                c->cipher,
                c->outer_key.data(), c->outer_key.size(),
                c->work_wire.data() + nlen, c->payload.size());
            std::memcpy(c->work_wire.data(), nonce.data(), nonce.size());
            (void)itb::wrapper::unwrap_in_place(
                c->cipher,
                c->outer_key.data(), c->outer_key.size(),
                c->work_wire.data(), c->work_wire.size());
        }
    };
    return bench::BenchCase{namebuf, std::move(run), kWrapperPayloadBytes};
}

// ----- Message benches ----------------------------------------------

bench::BenchCase make_message_encrypt_case(int mode, bool auth,
                                           itb::wrapper::Cipher cipher,
                                           const char* cipher_name,
                                           const char* label) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->mode = mode;
    ctx->auth = auth;
    ctx->cipher = cipher;
    ctx->enc = new_encryptor(mode, auth);
    ctx->payload = bench::random_bytes_vec(kMessagePayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    const char* mode_name = (mode == 1) ? "Single" : "Triple";
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkMessage%s/%s/%s/encrypt",
                  mode_name, label, cipher_name);
    bench::BenchFn run = [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; ++i) {
            auto ct = c->auth ? c->enc->encrypt_auth(c->payload)
                              : c->enc->encrypt(c->payload);
            auto wire = itb::wrapper::wrap(c->cipher,
                                           c->outer_key.data(), c->outer_key.size(),
                                           ct.data(), ct.size());
            (void)wire;
        }
    };
    return bench::BenchCase{namebuf, std::move(run), kMessagePayloadBytes};
}

bench::BenchCase make_message_decrypt_case(int mode, bool auth,
                                           itb::wrapper::Cipher cipher,
                                           const char* cipher_name,
                                           const char* label) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->mode = mode;
    ctx->auth = auth;
    ctx->cipher = cipher;
    ctx->enc = new_encryptor(mode, auth);
    ctx->payload = bench::random_bytes_vec(kMessagePayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);

    // Build pristine wire = wrap(encrypt(payload)) once; per-iter
    // refresh the work_wire from this snapshot.
    auto ct = ctx->auth ? ctx->enc->encrypt_auth(ctx->payload)
                        : ctx->enc->encrypt(ctx->payload);
    ctx->pristine_wire = itb::wrapper::wrap(ctx->cipher,
                                            ctx->outer_key.data(), ctx->outer_key.size(),
                                            ct.data(), ct.size());
    ctx->work_wire.resize(ctx->pristine_wire.size());
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    const char* mode_name = (mode == 1) ? "Single" : "Triple";
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkMessage%s/%s/%s/decrypt",
                  mode_name, label, cipher_name);
    bench::BenchFn run = [c](std::uint64_t iters) {
        for (std::uint64_t i = 0; i < iters; ++i) {
            std::memcpy(c->work_wire.data(),
                        c->pristine_wire.data(),
                        c->pristine_wire.size());
            auto recovered = itb::wrapper::unwrap(
                c->cipher,
                c->outer_key.data(), c->outer_key.size(),
                c->work_wire.data(), c->work_wire.size());
            auto pt = c->auth ? c->enc->decrypt_auth(recovered)
                              : c->enc->decrypt(recovered);
            (void)pt;
        }
    };
    return bench::BenchCase{namebuf, std::move(run), kMessagePayloadBytes};
}

// ----- Streaming benches --------------------------------------------
//
// 4 modes × 3 ciphers × 2 directions × {Single, Triple} = 48 cases.
// In the C++ binding the AEAD-Easy / AEAD-Low-Level pair both route
// through `Encryptor::stream_encrypt_auth` (callback-driven), and
// the No MAC Easy / Low-Level pair both go through the User-Driven
// Loop with `Encryptor::encrypt` per chunk — so the four labels
// exercise the same inner code paths but emit distinct case names so
// the surface count matches the cross-binding 24-per-mode total.

void put_u32_le(std::uint8_t* dst, std::uint32_t v) {
    dst[0] = static_cast<std::uint8_t>(v & 0xFFu);
    dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    dst[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    dst[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
}

std::uint32_t get_u32_le(const std::uint8_t* src) {
    return static_cast<std::uint32_t>(src[0])
         | (static_cast<std::uint32_t>(src[1]) << 8)
         | (static_cast<std::uint32_t>(src[2]) << 16)
         | (static_cast<std::uint32_t>(src[3]) << 24);
}

// AEAD streaming: encrypt the payload to an in-memory sink via
// `Encryptor::stream_encrypt_auth`; the binding's StreamSink callback
// accumulates the ITB-emitted bytestream into a vector.
std::vector<std::uint8_t> aead_encrypt_inner(itb::Encryptor& enc,
                                             const std::vector<std::uint8_t>& payload,
                                             std::size_t chunk_size) {
    std::vector<std::uint8_t> out;
    out.reserve(payload.size() + (payload.size() / 16) + 256);
    std::size_t pos = 0;
    enc.stream_encrypt_auth(
        [&payload, &pos](std::uint8_t* buf, std::size_t cap) -> std::size_t {
            std::size_t avail = payload.size() - pos;
            std::size_t take = (cap < avail) ? cap : avail;
            if (take > 0) {
                std::memcpy(buf, payload.data() + pos, take);
                pos += take;
            }
            return take;
        },
        [&out](const std::uint8_t* buf, std::size_t n) {
            out.insert(out.end(), buf, buf + n);
        },
        chunk_size);
    return out;
}

std::vector<std::uint8_t> aead_decrypt_inner(itb::Encryptor& enc,
                                             const std::vector<std::uint8_t>& inner,
                                             std::size_t chunk_size) {
    std::vector<std::uint8_t> out;
    out.reserve(inner.size());
    std::size_t pos = 0;
    enc.stream_decrypt_auth(
        [&inner, &pos](std::uint8_t* buf, std::size_t cap) -> std::size_t {
            std::size_t avail = inner.size() - pos;
            std::size_t take = (cap < avail) ? cap : avail;
            if (take > 0) {
                std::memcpy(buf, inner.data() + pos, take);
                pos += take;
            }
            return take;
        },
        [&out](const std::uint8_t* buf, std::size_t n) {
            out.insert(out.end(), buf, buf + n);
        },
        chunk_size);
    return out;
}

// User-Driven Loop: per-chunk encrypt; emit u32_LE_len || ct through
// the wrap-writer.
void encrypt_userloop_inner(itb::Encryptor& enc,
                            const std::vector<std::uint8_t>& payload,
                            std::vector<std::uint8_t>& wire_out,
                            itb::wrapper::WrapStreamWriter& ww,
                            std::size_t chunk_size) {
    for (std::size_t off = 0; off < payload.size(); off += chunk_size) {
        std::size_t take = payload.size() - off;
        if (take > chunk_size) take = chunk_size;
        auto ct = enc.encrypt(payload.data() + off, take);
        std::uint8_t hdr[4];
        put_u32_le(hdr, static_cast<std::uint32_t>(ct.size()));
        auto hdr_xor = ww.update(hdr, 4);
        wire_out.insert(wire_out.end(), hdr_xor.begin(), hdr_xor.end());
        auto ct_xor = ww.update(ct.data(), ct.size());
        wire_out.insert(wire_out.end(), ct_xor.begin(), ct_xor.end());
    }
}

void decrypt_userloop_inner(itb::Encryptor& enc,
                            itb::wrapper::UnwrapStreamReader& ur,
                            const std::uint8_t* body,
                            std::size_t body_len,
                            std::vector<std::uint8_t>& pt_out) {
    std::size_t off = 0;
    while (off < body_len) {
        if (off + 4 > body_len) break;
        auto hdr_xor = ur.update(body + off, 4);
        off += 4;
        auto clen = get_u32_le(hdr_xor.data());
        if (off + clen > body_len) break;
        auto ct = ur.update(body + off, clen);
        off += clen;
        auto pt = enc.decrypt(ct);
        pt_out.insert(pt_out.end(), pt.begin(), pt.end());
    }
}

enum class StreamKind {
    AeadEasyIo,
    AeadLowLevelIo,
    NoAeadEasyUserloop,
    NoAeadLowLevelUserloop,
};

bool is_aead(StreamKind k) {
    return k == StreamKind::AeadEasyIo || k == StreamKind::AeadLowLevelIo;
}

bench::BenchCase make_stream_encrypt_case(int mode, StreamKind kind,
                                          itb::wrapper::Cipher cipher,
                                          const char* cipher_name,
                                          const char* label) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->mode = mode;
    ctx->auth = is_aead(kind);
    ctx->cipher = cipher;
    ctx->enc = new_encryptor(mode, ctx->auth);
    ctx->payload = bench::random_bytes_vec(kStreamPayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    const char* mode_name = (mode == 1) ? "Single" : "Triple";
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkStreaming%s/%s/%s/encrypt",
                  mode_name, label, cipher_name);

    bench::BenchFn run;
    if (is_aead(kind)) {
        run = [c](std::uint64_t iters) {
            for (std::uint64_t i = 0; i < iters; ++i) {
                auto inner = aead_encrypt_inner(*c->enc, c->payload, kStreamChunkBytes);
                itb::wrapper::WrapStreamWriter ww{c->cipher,
                                                  c->outer_key.data(), c->outer_key.size()};
                std::vector<std::uint8_t> wire;
                wire.reserve(ww.nonce().size() + inner.size());
                wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
                auto body_xor = ww.update(inner.data(), inner.size());
                wire.insert(wire.end(), body_xor.begin(), body_xor.end());
            }
        };
    } else {
        run = [c](std::uint64_t iters) {
            for (std::uint64_t i = 0; i < iters; ++i) {
                std::vector<std::uint8_t> wire;
                wire.reserve(c->payload.size() + (c->payload.size() / 16) + 256);
                itb::wrapper::WrapStreamWriter ww{c->cipher,
                                                  c->outer_key.data(), c->outer_key.size()};
                wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
                encrypt_userloop_inner(*c->enc, c->payload, wire, ww, kStreamChunkBytes);
            }
        };
    }
    return bench::BenchCase{namebuf, std::move(run), kStreamPayloadBytes};
}

void prime_pristine_aead(CaseCtx& c) {
    auto inner = aead_encrypt_inner(*c.enc, c.payload, kStreamChunkBytes);
    itb::wrapper::WrapStreamWriter ww{c.cipher,
                                      c.outer_key.data(), c.outer_key.size()};
    c.pristine_wire.clear();
    c.pristine_wire.reserve(ww.nonce().size() + inner.size());
    c.pristine_wire.insert(c.pristine_wire.end(),
                           ww.nonce().begin(), ww.nonce().end());
    auto body_xor = ww.update(inner.data(), inner.size());
    c.pristine_wire.insert(c.pristine_wire.end(),
                           body_xor.begin(), body_xor.end());
    c.work_wire.resize(c.pristine_wire.size());
}

void prime_pristine_userloop(CaseCtx& c) {
    std::vector<std::uint8_t> wire;
    wire.reserve(c.payload.size() + (c.payload.size() / 16) + 256);
    itb::wrapper::WrapStreamWriter ww{c.cipher,
                                      c.outer_key.data(), c.outer_key.size()};
    wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
    encrypt_userloop_inner(*c.enc, c.payload, wire, ww, kStreamChunkBytes);
    c.pristine_wire = std::move(wire);
    c.work_wire.resize(c.pristine_wire.size());
}

bench::BenchCase make_stream_decrypt_case(int mode, StreamKind kind,
                                          itb::wrapper::Cipher cipher,
                                          const char* cipher_name,
                                          const char* label) {
    auto ctx = std::make_unique<CaseCtx>();
    ctx->mode = mode;
    ctx->auth = is_aead(kind);
    ctx->cipher = cipher;
    ctx->enc = new_encryptor(mode, ctx->auth);
    ctx->payload = bench::random_bytes_vec(kStreamPayloadBytes);
    ctx->outer_key = itb::wrapper::generate_key(cipher);

    if (is_aead(kind)) {
        prime_pristine_aead(*ctx);
    } else {
        prime_pristine_userloop(*ctx);
    }
    auto* c = register_ctx(std::move(ctx));

    char namebuf[128];
    const char* mode_name = (mode == 1) ? "Single" : "Triple";
    std::snprintf(namebuf, sizeof(namebuf),
                  "BenchmarkStreaming%s/%s/%s/decrypt",
                  mode_name, label, cipher_name);

    bench::BenchFn run;
    if (is_aead(kind)) {
        run = [c](std::uint64_t iters) {
            std::size_t nlen = itb::wrapper::nonce_size(c->cipher);
            for (std::uint64_t i = 0; i < iters; ++i) {
                std::memcpy(c->work_wire.data(),
                            c->pristine_wire.data(),
                            c->pristine_wire.size());
                itb::wrapper::UnwrapStreamReader ur{c->cipher,
                                                    c->outer_key.data(), c->outer_key.size(),
                                                    c->work_wire.data(), nlen};
                auto inner = ur.update(c->work_wire.data() + nlen,
                                       c->work_wire.size() - nlen);
                auto pt = aead_decrypt_inner(*c->enc, inner, kStreamChunkBytes);
                (void)pt;
            }
        };
    } else {
        run = [c](std::uint64_t iters) {
            std::size_t nlen = itb::wrapper::nonce_size(c->cipher);
            for (std::uint64_t i = 0; i < iters; ++i) {
                std::memcpy(c->work_wire.data(),
                            c->pristine_wire.data(),
                            c->pristine_wire.size());
                itb::wrapper::UnwrapStreamReader ur{c->cipher,
                                                    c->outer_key.data(), c->outer_key.size(),
                                                    c->work_wire.data(), nlen};
                std::vector<std::uint8_t> pt;
                decrypt_userloop_inner(*c->enc, ur,
                                       c->work_wire.data() + nlen,
                                       c->work_wire.size() - nlen,
                                       pt);
                (void)pt;
            }
        };
    }
    return bench::BenchCase{namebuf, std::move(run), kStreamPayloadBytes};
}

// ----- Case-list assembly -------------------------------------------

constexpr std::size_t kTotalCases = 102;

std::vector<bench::BenchCase> build_cases() {
    std::vector<bench::BenchCase> cases;
    cases.reserve(kTotalCases);

    // Wrapper Only — 6 cases.
    for (std::size_t ci = 0; ci < kCipherCount; ++ci) {
        cases.push_back(make_wrapper_only_wrap_case(kCiphers[ci], kCipherNames[ci]));
        cases.push_back(make_wrapper_only_inplace_case(kCiphers[ci], kCipherNames[ci]));
    }

    // Message — 4 modes × 3 ciphers × 2 dirs × {Single, Triple} = 48.
    struct MsgLabel { const char* label; bool auth; };
    static const MsgLabel kMsgLabels[] = {
        { "easy-nomac",      false },
        { "easy-auth",       true  },
        { "lowlevel-nomac",  false },
        { "lowlevel-auth",   true  },
    };
    static const int kModes[] = { 1, 3 };
    for (int mode : kModes) {
        for (const auto& m : kMsgLabels) {
            for (std::size_t ci = 0; ci < kCipherCount; ++ci) {
                cases.push_back(make_message_encrypt_case(
                    mode, m.auth, kCiphers[ci], kCipherNames[ci], m.label));
                cases.push_back(make_message_decrypt_case(
                    mode, m.auth, kCiphers[ci], kCipherNames[ci], m.label));
            }
        }
    }

    // Streaming — 4 modes × 3 ciphers × 2 dirs × {Single, Triple} = 48.
    struct StreamLabel { const char* label; StreamKind kind; };
    static const StreamLabel kStreamLabels[] = {
        { "aead-easy-io",             StreamKind::AeadEasyIo             },
        { "aead-lowlevel-io",         StreamKind::AeadLowLevelIo         },
        { "noaead-easy-userloop",     StreamKind::NoAeadEasyUserloop     },
        { "noaead-lowlevel-userloop", StreamKind::NoAeadLowLevelUserloop },
    };
    for (int mode : kModes) {
        for (const auto& s : kStreamLabels) {
            for (std::size_t ci = 0; ci < kCipherCount; ++ci) {
                cases.push_back(make_stream_encrypt_case(
                    mode, s.kind, kCiphers[ci], kCipherNames[ci], s.label));
                cases.push_back(make_stream_decrypt_case(
                    mode, s.kind, kCiphers[ci], kCipherNames[ci], s.label));
            }
        }
    }

    return cases;
}

} // namespace

int main() {
    try {
        int nonce_bits = bench::env_nonce_bits(128);
        itb::set_max_workers(0);
        itb::set_nonce_bits(nonce_bits);

        std::printf("# wrapper bench primitive=%s key_bits=%d mac=%s "
                    "ciphers=%zu cases=%zu nonce_bits=%d workers=auto\n",
                    kBenchPrimitive, kBenchKeyBits, kBenchMacName,
                    kCipherCount, kTotalCases, nonce_bits);
        std::fflush(stdout);

        auto cases = build_cases();
        if (cases.size() != kTotalCases) {
            std::fprintf(stderr,
                         "build_cases yielded %zu, expected %zu\n",
                         cases.size(), kTotalCases);
            return 1;
        }
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
