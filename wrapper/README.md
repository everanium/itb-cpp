# ITB Format-Deniability Wrapper — C++ Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

C++-idiomatic surface over the 12 `ITB_Wrap*` / `ITB_Unwrap*` / `ITB_WrapStream*` / `ITB_UnwrapStream*` / `ITB_WrapperKeySize` / `ITB_WrapperNonceSize` exports in `cmd/cshared/main.go`. Wraps an ITB ciphertext under one of outer keystream ciphers, each in CTR mode, so the on-wire bytes carry no ITB-specific format pattern (W / H / container layout for Non-AEAD; 32-byte stream-id prefix + per-chunk metadata for Streaming AEAD). The wrap exists for **format-deniability ONLY** — ITB already provides content-deniability and the AEAD path already provides integrity.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte stream-id prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte stream-id prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The C++ binding exposes the wrap surface in `include/itb/wrapper.hpp` under `namespace itb::wrapper`. Two flavours of helpers, picked per use case:

| Helper | Wire format | Use case |
|---|---|---|
| `wrap` / `unwrap` | `nonce` + keystream-XOR(blob) | Single Message Encrypt / EncryptAuth output (separately allocated wire buffer) |
| `wrap_in_place` / `unwrap_in_place` | `nonce` separate, body XORed in place | no output-buffer allocation on the hot path; mutates the caller's blob / wire |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — AEAD IO-Driven, or User-Driven Loop where caller-side framing (e.g. per-chunk `u32_LE` length prefixes) is written through the wrap-writer so the framing bytes also pass through the keystream XOR |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

The wrap surface compiles against the C++17 baseline shared by the rest of the binding. Public API entry points take `const std::uint8_t* + std::size_t` / `std::uint8_t* + std::size_t` pointer+length pairs; `unwrap_in_place` returns a `std::pair<std::uint8_t*, std::size_t>` over the recovered body. Consumers do not need to flip to C++20.

## Outer ciphers

| Cipher | Enum | FFI name | Key | Nonce | Notes |
|---|---|---|---|---|---|
| Areion-SoEM-256 in CTR mode | `Cipher::Areion256` | `"areion256"` | 32 B | 16 B | AES-round-based PRF in CTR mode. Sound under standard PRF assumption. |
| Areion-SoEM-512 in CTR mode | `Cipher::Areion512` | `"areion512"` | 64 B | 16 B | Wider Areion PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE2b-256 in CTR mode | `Cipher::Blake2b256` | `"blake2b256"` | 32 B | 16 B | Keyed BLAKE2b PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE2b-512 in CTR mode | `Cipher::Blake2b512` | `"blake2b512"` | 32 B | 16 B | Keyed BLAKE2b PRF (512-bit output) in CTR mode. Sound under standard PRF assumption. |
| BLAKE2s in CTR mode | `Cipher::Blake2s` | `"blake2s"` | 32 B | 16 B | Keyed BLAKE2s PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE3 in CTR mode | `Cipher::Blake3` | `"blake3"` | 32 B | 16 B | Keyed BLAKE3 PRF in CTR mode. Sound under standard PRF assumption. |
| AES-128-CTR | `Cipher::Aes128Ctr` | `"aescmac"` | 16 B | 16 B | stdlib `crypto/aes` + `crypto/cipher.NewCTR`. AES-NI accelerated. |
| SipHash-2-4 in CTR mode | `Cipher::SipHash24` | `"siphash24"` | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |
| ChaCha20 (RFC8439) | `Cipher::ChaCha20` | `"chacha20"` | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash128(key, nonce_hi || (nonce_lo XOR counter_LE))` — 16-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

The eitb runner under `bindings/cpp/eitb/eitb.cpp` exercises every example × cipher combination end-to-end. Build and run:

```sh
make eitb
./eitb/build/eitb              # 72 PASS, 0 FAIL
./eitb/build/eitb --example aead
./eitb/build/eitb --cipher aes
./eitb/build/eitb -v
```

Eight examples cover the full streaming + Single Message matrix. The C++ binding has **no Streaming No MAC IO-Driven** examples (there is no `std::ostream` / `std::istream` wrapper writer / reader pair for Non-AEAD streaming); the No MAC streaming arm uses the User-Driven Loop only.

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Encryptor::stream_encrypt_auth` / `stream_decrypt_auth` over a `StreamSink` callback. Wrap shape: one `WrapStreamWriter` session over the entire bytestream the inner stream encoder emits.

```cpp
itb::Encryptor enc{"areion512", 1024, "hmac-blake3", 1};
auto outer_key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);

// Sender: encrypt to in-memory sink, then wrap end-to-end.
std::vector<std::uint8_t> inner;
enc.stream_encrypt_auth(read_fn, [&inner](const std::uint8_t* b, std::size_t n) {
    inner.insert(inner.end(), b, b + n);
});

itb::wrapper::WrapStreamWriter ww{itb::wrapper::Cipher::Aes128Ctr,
                                  outer_key.data(), outer_key.size()};
std::vector<std::uint8_t> wire;
wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
auto inner_xor = ww.update(inner.data(), inner.size());
wire.insert(wire.end(), inner_xor.begin(), inner_xor.end());
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb::encrypt_stream_auth` / `itb::decrypt_stream_auth` with three explicit `itb::Seed` instances + an `itb::Mac` (HMAC-BLAKE3). Wrap shape: as above.

### 3. Streaming Easy (No MAC, User-Driven Loop)

The Go README's "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.encrypt(buf)` call. Wrap shape: `WrapStreamWriter` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrap-writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb::encrypt` / `itb::decrypt` with caller-side framing. Wrap shape as in example 3.

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.encrypt(plaintext)` returns one ITB blob. Wrap shape: `wrap_in_place` mutates the blob, returns the per-stream nonce; the caller composes `nonce || mutated-blob` to produce the wire. Receiver `unwrap_in_place` mutates the wire and the returned span covers the recovered body.

```cpp
auto encrypted = enc.encrypt(plaintext);
auto outer_key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);

auto nonce = itb::wrapper::wrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outer_key.data(), outer_key.size(),
    encrypted.data(), encrypted.size());

std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
std::copy(nonce.begin(), nonce.end(), wire.begin());
std::copy(encrypted.begin(), encrypted.end(),
          wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

// Receiver.
auto body = itb::wrapper::unwrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outer_key.data(), outer_key.size(),
    wire.data(), wire.size());
auto pt = enc.decrypt(
    std::vector<std::uint8_t>(body.first, body.first + body.second));
```

The immutable-input alternative uses `itb::wrapper::wrap` / `itb::wrapper::unwrap`, which allocate a fresh wire buffer at the cost of one extra allocation per call. The eitb runner exercises both via commented alternatives.

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.encrypt_auth` / `enc.decrypt_auth`. Wrap shape: as in example 5. The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb::encrypt(noise, data, start, plaintext)` / `itb::decrypt(...)` with three explicit `itb::Seed` instances built from `itb::Seed{"areion512", 2048}`. Wrap shape as in example 5.

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb::encrypt_auth` / `itb::decrypt_auth` with the MAC closure constructed via `itb::Mac{"hmac-blake3", mac_key}`. Wrap shape as in example 5.

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + areion256   pt=65536 wire=90016
[PASS] aead-easy-io               + areion512   pt=65536 wire=90016
[PASS] aead-easy-io               + blake2b256   pt=65536 wire=90016
[PASS] aead-easy-io               + blake2b512   pt=65536 wire=90016
[PASS] aead-easy-io               + blake2s    pt=65536 wire=90016
[PASS] aead-easy-io               + blake3     pt=65536 wire=90016
[PASS] aead-easy-io               + aescmac    pt=65536 wire=90016
[PASS] aead-easy-io               + siphash24   pt=65536 wire=90016
[PASS] aead-easy-io               + chacha20   pt=65536 wire=90012
...
[PASS] message-lowlevel-auth      + areion256   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + areion512   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2b256   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2b512   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2s    pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake3     pt=1024 wire=8228
[PASS] message-lowlevel-auth      + aescmac    pt=1024 wire=8228
[PASS] message-lowlevel-auth      + siphash24   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + chacha20   pt=1024 wire=8224
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (12 bytes for ChaCha20, 16 bytes for every other outer cipher); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md). Total sub-bench count: 102 (6 wrapper only round-trip + 24 Message Single + 24 Message Triple + 24 Streaming Single + 24 Streaming Triple).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the eitb runner generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## Threading

The Single Message `wrap` / `unwrap` / `wrap_in_place` / `unwrap_in_place` are thread-safe: each call constructs an outer cipher session of its own and the libitb keystream constructor draws a fresh CSPRNG nonce per call. The streaming `WrapStreamWriter` / `UnwrapStreamReader` handles are single-feeder — every `update` call advances the underlying keystream counter; concurrent `update` calls on the same handle race. Distinct handles run independently.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
