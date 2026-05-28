# ITB Format-Deniability Wrapper Benchmark Results — C++ Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's callback-driven Streaming AEAD API or a User-Driven Loop emitting framed chunks through the wrap-stream writer.

The wrapper bench covers all  outer ciphers — each in CTR mode.

### Concurrency note — outer cipher throughput on big-iron

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The C++ binding routes XOR through a single libitb FFI call; the parallelisation across up to 32 goroutines happens inside libitb for buffers at or above the 256 KiB threshold, so the binding adds only per-call FFI-crossing overhead on top of the parallel XOR.

## Binding asymmetry note

The C++ binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
cd bindings/cpp
make bench
ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=BenchmarkWrapperOnlyInPlace ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
ITB_BENCH_FILTER=BenchmarkMessageSingle/easy-nomac ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
ITB_BENCH_FILTER=BenchmarkStreamingTriple ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
```

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb::set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `std::memcpy`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 597 | 1778 |
| **Areion-SoEM-512** | 604 | 1812 |
| **BLAKE2b-256** | 368 | 628 |
| **BLAKE2b-512** | 484 | 1032 |
| **BLAKE2s** | 390 | 681 |
| **BLAKE3** | 523 | 1213 |
| **AES-128-CTR** | 739 | 4298 |
| **SipHash-2-4** | 675 | 2354 |
| **ChaCha20** | 660 | 2271 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 129 | 260 | 135 | 249 | 144 | 268 | 136 | 250 |
| **Areion-SoEM-512** | 145 | 269 | 137 | 250 | 144 | 270 | 137 | 249 |
| **BLAKE2b-256** | 133 | 231 | 127 | 215 | 134 | 230 | 127 | 216 |
| **BLAKE2b-512** | 141 | 253 | 133 | 237 | 139 | 253 | 132 | 236 |
| **BLAKE2s** | 134 | 233 | 127 | 220 | 134 | 231 | 128 | 220 |
| **BLAKE3** | 143 | 259 | 134 | 240 | 143 | 259 | 134 | 239 |
| **AES-128-CTR** | 149 | 277 | 140 | 255 | 148 | 277 | 141 | 255 |
| **SipHash-2-4** | 146 | 274 | 138 | 254 | 145 | 275 | 139 | 253 |
| **ChaCha20** | 148 | 274 | 139 | 252 | 148 | 273 | 142 | 253 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 180 | 296 | 168 | 276 | 183 | 297 | 167 | 275 |
| **Areion-SoEM-512** | 180 | 298 | 170 | 279 | 178 | 293 | 170 | 279 |
| **BLAKE2b-256** | 163 | 250 | 153 | 236 | 164 | 250 | 152 | 236 |
| **BLAKE2b-512** | 173 | 278 | 161 | 262 | 174 | 274 | 162 | 262 |
| **BLAKE2s** | 165 | 255 | 154 | 242 | 165 | 255 | 154 | 242 |
| **BLAKE3** | 176 | 284 | 164 | 266 | 176 | 284 | 165 | 267 |
| **AES-128-CTR** | 185 | 308 | 174 | 289 | 184 | 310 | 175 | 285 |
| **SipHash-2-4** | 182 | 303 | 170 | 285 | 182 | 303 | 170 | 286 |
| **ChaCha20** | 186 | 304 | 172 | 285 | 185 | 303 | 172 | 283 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 124 | 174 | 124 | 175 |
| **Areion-SoEM-512** | 125 | 176 | 125 | 177 |
| **BLAKE2b-256** | 118 | 161 | 118 | 161 |
| **BLAKE2b-512** | 123 | 171 | 122 | 172 |
| **BLAKE2s** | 118 | 162 | 118 | 163 |
| **BLAKE3** | 123 | 174 | 123 | 174 |
| **AES-128-CTR** | 126 | 180 | 126 | 179 |
| **SipHash-2-4** | 126 | 178 | 126 | 179 |
| **ChaCha20** | 126 | 177 | 126 | 178 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 156 | 203 | 155 | 202 |
| **Areion-SoEM-512** | 157 | 203 | 157 | 203 |
| **BLAKE2b-256** | 145 | 181 | 144 | 181 |
| **BLAKE2b-512** | 153 | 196 | 151 | 195 |
| **BLAKE2s** | 145 | 183 | 146 | 182 |
| **BLAKE3** | 155 | 198 | 154 | 199 |
| **AES-128-CTR** | 160 | 207 | 161 | 207 |
| **SipHash-2-4** | 159 | 204 | 159 | 204 |
| **ChaCha20** | 148 | 204 | 158 | 204 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 147 | 197 | 152 | 201 |
| **Areion-SoEM-512** | 152 | 200 | 150 | 201 |
| **BLAKE2b-256** | 140 | 178 | 140 | 180 |
| **BLAKE2b-512** | 148 | 192 | 148 | 193 |
| **BLAKE2s** | 141 | 180 | 141 | 182 |
| **BLAKE3** | 150 | 194 | 150 | 196 |
| **AES-128-CTR** | 155 | 205 | 156 | 206 |
| **SipHash-2-4** | 155 | 204 | 154 | 205 |
| **ChaCha20** | 153 | 202 | 154 | 203 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 199 | 218 | 197 | 217 |
| **Areion-SoEM-512** | 199 | 218 | 199 | 218 |
| **BLAKE2b-256** | 176 | 192 | 176 | 192 |
| **BLAKE2b-512** | 188 | 208 | 189 | 207 |
| **BLAKE2s** | 179 | 194 | 177 | 193 |
| **BLAKE3** | 193 | 211 | 191 | 211 |
| **AES-128-CTR** | 202 | 224 | 202 | 224 |
| **SipHash-2-4** | 200 | 223 | 198 | 220 |
| **ChaCha20** | 201 | 222 | 199 | 221 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
