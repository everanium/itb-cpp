# ITB C++ Binding — Easy Mode Benchmark Results

Throughput (MB/s) of `Encryptor::encrypt` / `decrypt` / `encrypt_auth` /
`decrypt_auth` over the libitb shared library through the C binding's
static archive (`-litb_c -litb`). Single + Triple Ouroboros at 1024-bit
ITB key width on a 16 MiB CSPRNG-filled payload, four ops per primitive.
MAC slot bound to **HMAC-BLAKE3** — the lightest authenticated-mode
overhead among the three shipping MACs.

Harness lives under [bench/](.) — see [bench/README.md](README.md) for
invocation, environment variables, and per-case output format. Default
measurement window is 5 seconds per case (`ITB_BENCH_MIN_SEC=5`).

## FFI overhead vs. native Go

The C++ binding routes every call through the C binding's `itb_*` static
archive. The C binding caches the libitb FFI write buffer per encryptor
(1.25× upper bound on the empirical ciphertext-expansion factor of
≤ 1.155) and hands the C++ wrapper a freshly malloc'd user-owned copy on
every cipher call; the C++ wrapper copies that buffer into a
`std::vector<std::uint8_t>` and frees the C-allocated pointer via
`itb_buffer_free`. The double-allocation overhead is the documented
trade-off for keeping the C++ surface header-only over the audited C
binding rather than wrapping raw libitb directly.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 185 | 285 | 176 | 256 |
| **Areion-SoEM-512** | 512 | PRF | 200 | 288 | 184 | 268 |
| **SipHash-2-4** | 128 | PRF | 148 | 191 | 140 | 182 |
| **AES-CMAC** | 128 | PRF | 183 | 256 | 169 | 239 |
| **BLAKE2b-512** | 512 | PRF | 134 | 169 | 127 | 161 |
| **BLAKE2b-256** | 256 | PRF | 94 | 109 | 89 | 105 |
| **BLAKE2s** | 256 | PRF | 102 | 118 | 98 | 114 |
| **BLAKE3** | 256 | PRF | 122 | 148 | 116 | 141 |
| **ChaCha20** | 256 | PRF | 107 | 128 | 104 | 121 |
| **Mixed** | 256 | PRF | 107 | 125 | 101 | 123 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 260 | 313 | 233 | 292 |
| **Areion-SoEM-512** | 512 | PRF | 270 | 325 | 244 | 307 |
| **SipHash-2-4** | 128 | PRF | 180 | 200 | 171 | 196 |
| **AES-CMAC** | 128 | PRF | 241 | 282 | 202 | 262 |
| **BLAKE2b-512** | 512 | PRF | 160 | 173 | 150 | 169 |
| **BLAKE2b-256** | 256 | PRF | 103 | 110 | 100 | 109 |
| **BLAKE2s** | 256 | PRF | 113 | 120 | 106 | 117 |
| **BLAKE3** | 256 | PRF | 139 | 152 | 132 | 147 |
| **ChaCha20** | 256 | PRF | 125 | 134 | 118 | 130 |
| **Mixed** | 256 | PRF | 124 | 130 | 118 | 129 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`enc.set_lock_seed(1)` / `ITB_LOCKSEED=1`)
auto-couples Bit Soup + Lock Soup. Numbers below run with all three overlays
active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 58 | 62 | 58 | 67 |
| **Areion-SoEM-512** | 512 | PRF | 49 | 54 | 48 | 53 |
| **SipHash-2-4** | 128 | PRF | 68 | 70 | 60 | 75 |
| **AES-CMAC** | 128 | PRF | 77 | 88 | 75 | 85 |
| **BLAKE2b-512** | 512 | PRF | 45 | 48 | 44 | 51 |
| **BLAKE2b-256** | 256 | PRF | 41 | 45 | 35 | 37 |
| **BLAKE2s** | 256 | PRF | 36 | 39 | 36 | 46 |
| **BLAKE3** | 256 | PRF | 43 | 45 | 42 | 46 |
| **ChaCha20** | 256 | PRF | 43 | 44 | 43 | 45 |
| **Mixed** | 256 | PRF | 49 | 56 | 50 | 52 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 57 | 63 | 60 | 62 |
| **Areion-SoEM-512** | 512 | PRF | 48 | 54 | 49 | 54 |
| **SipHash-2-4** | 128 | PRF | 69 | 72 | 66 | 72 |
| **AES-CMAC** | 128 | PRF | 76 | 80 | 74 | 80 |
| **BLAKE2b-512** | 512 | PRF | 48 | 50 | 47 | 46 |
| **BLAKE2b-256** | 256 | PRF | 44 | 45 | 43 | 44 |
| **BLAKE2s** | 256 | PRF | 44 | 46 | 44 | 47 |
| **BLAKE3** | 256 | PRF | 43 | 45 | 43 | 44 |
| **ChaCha20** | 256 | PRF | 48 | 50 | 38 | 45 |
| **Mixed** | 256 | PRF | 48 | 50 | 47 | 49 |

## Notes

- The first row in every Single-Ouroboros pass typically shows a transient
  asymmetry between encrypt and decrypt — the cold-cache + first-iteration
  warm-up absorbed imperfectly even at the 5-second window. Subsequent rows
  run on warm caches and report symmetric encrypt-vs-decrypt numbers.
  Re-running the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 ./bench/build/bench_single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 40-80 MB/s band because the
  dedicated lockseed slot auto-engages Bit Soup + Lock Soup; the bit-level
  split + per-chunk PRF-keyed bit-permutation overlay together dominate the
  per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most primitives
  because the seven-seed split exposes additional internal parallelism
  opportunities to libitb's worker pool while the on-the-wire chunk count
  remains the same.
- Bench cases run sequentially per pass; libitb's internal worker pool
  (`itb::set_max_workers(0)` → all CPUs) processes each case's chunk-level
  parallelism within the case's wall-clock window.

