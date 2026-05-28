# ITB C++ Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

C++17 RAII wrapper over the libitb shared library (`cmd/cshared`).
Header-only: consumers include `<itb.hpp>` (or the finer-grained headers
under `<itb/...>`) and link against the C binding's static archive plus
`libitb.so`. Every fallible `itb_*` status surfaces as a typed exception
derived from `itb::ItbError`; every opaque handle is owned by a move-only
RAII type that releases on destruction.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-cpp`. Substitute the literal
token in the recipes below; shell does not expand it.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools gcc clang make cmake pkgconf check catch2
```

`gcc` is the reference compiler; `clang` is exercised by the same
Makefile (`CXX=clang++ make`). `pkgconf` resolves `pkg-config --cflags
check` for the C-binding test runner; `catch2` is the C++17 framework
powering `tests/test_*.cpp`. Consumer applications linking
`libitb_c.a` plus `libitb.so` need none of the test-side packages — the
runtime surface uses only the C++17 standard library.

## Build the shared library

Run `bindings/cpp/build.sh` from anywhere to chain every prerequisite
build in one step:

```bash
./bindings/cpp/build.sh
```

Three underlying steps: build `libitb.so` from repo root, build
`libitb_c.a` via the C binding's Makefile, run `check_header.sh` to
verify `include/itb.h` has not drifted from
`bindings/c/include/itb.h`. The C++ wrappers themselves are
header-only. Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/c && make
cd ../cpp && ./check_header.sh
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

### Compiler selection

Both compilers accept the source unchanged at `-std=c++17`:

```bash
CXX=g++     make tests   # reference compiler
CXX=clang++ make tests   # LLVM-backed compiler
```

The Makefile ships a strict warning baseline (`-Wall -Wextra -Wpedantic
-Wshadow -Wconversion -Wsign-conversion -Wold-style-cast
-Wnon-virtual-dtor -Woverloaded-virtual`) on top of `-O2 -fPIC`. Headers,
tests, and bench harness build clean under both compilers at this flag
set.

## Add to a C++ project

Compile against the public headers and link the static archive plus
`libitb.so`:

```bash
c++ -std=c++17 -O2 \
    -I/path/to/bindings/cpp/include \
    -I/path/to/bindings/c/include \
    myapp.cpp \
    -L/path/to/bindings/c/build -litb_c \
    -L/path/to/dist/linux-amd64 -Wl,-rpath,/path/to/dist/linux-amd64 \
    -litb
```

For CMake-driven projects, the binding ships a minimal `INTERFACE`
target carrying the C++ + C binding include directories transitively.
The consumer adds the static archive plus `libitb.so` against its own
executable target:

```cmake
add_subdirectory(third_party/itb/bindings/cpp)
target_link_libraries(my_app PRIVATE itb)
target_link_libraries(my_app PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/itb/bindings/c/build/libitb_c.a
    -L${CMAKE_SOURCE_DIR}/third_party/itb/dist/linux-amd64 -litb)
```

## Library lookup order

Every `itb::*` wrapper resolves at link time against `libitb_c.a` plus
`libitb.so`. Runtime resolution of the shared library at process start
follows the standard dynamic-linker order:

1. `LD_LIBRARY_PATH` resolved at process startup.
2. The `rpath` baked at link time
   (`-Wl,-rpath,../../dist/linux-amd64`). The Makefile and the CMake
   snippet above embed this so installed binaries find `libitb`
   without `LD_LIBRARY_PATH`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```cpp
itb::set_memory_limit(512LL << 20);
itb::set_gc_percent(20);
```

## Tests

```bash
cd bindings/cpp/
make tests       # compile every tests/test_*.cpp into tests/build/test_*
make test        # tests + run via run_tests.sh
./run_tests.sh
```

The 41 test files cover Single + Triple round-trip across each PRF
primitive, authenticated paths, mixed primitives, persistence and
native blob round-trip, streaming chunked I/O, nonce-size variants,
lockSeed lifecycle, closed-state preflight, empty-payload rejection,
the typed exception hierarchy, and `last_mismatch_field()`. Each test
compiles to a standalone executable under `tests/build/` linked
against `build/libitb_c.a` + `libitb.so` + Catch2 v3. Per-process
isolation gives every test a fresh libitb global state.

Filter via `ITB_TEST_FILTER`, forwarded to Catch2's filter syntax:

```bash
ITB_TEST_FILTER='[blake3]' ./run_tests.sh
```

## Benchmarks

Throughput numbers live in [`bench/BENCH.md`](bench/BENCH.md); see
[`bench/README.md`](bench/README.md) for invocation, environment
variables, and per-case output format. The harness covers four ops
across PRF-grade primitives plus one mixed variant for both
Single and Triple at 1024-bit ITB key width and 16 MiB payload.
Four-pass sweep:

```bash
cd bindings/cpp/
make bench
./run_bench.sh                  # full 4-pass canonical sweep
```

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

**Easy Mode:**

`itb::Encryptor::stream_encrypt_auth` accepts a `StreamSource`
(`std::function<std::size_t(std::uint8_t*, std::size_t)>`) and a
`StreamSink` (`std::function<void(const std::uint8_t*, std::size_t)>`).
Closures capturing `std::ifstream` / `std::ofstream` by reference adapt
file streams to the binding's callback shape. The MAC key is allocated
CSPRNG-fresh inside the encryptor at constructor time.

```cpp
#include <fstream>
#include <itb.hpp>
#include <itb/wrapper.hpp>
#include <vector>

constexpr std::size_t kChunkSize = std::size_t(16) * 1024 * 1024;

auto make_reader = [](std::ifstream& in) {
    return [&in](std::uint8_t* buf, std::size_t cap) -> std::size_t {
        in.read(reinterpret_cast<char*>(buf), cap);
        return static_cast<std::size_t>(in.gcount());
    };
};
auto make_writer = [](std::ofstream& out) {
    return [&out](const std::uint8_t* buf, std::size_t n) {
        out.write(reinterpret_cast<const char*>(buf), n);
    };
};

itb::Encryptor enc{"areion512", 1024, "hmac-blake3", 1};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Sender — collect the inner ITB stream in memory, then wrap the
// transcript end-to-end through one keystream session before flushing
// to the wire.
{
    std::vector<std::uint8_t> inner;
    std::ifstream fin("/tmp/64mb.src", std::ios::binary);
    enc.stream_encrypt_auth(
        make_reader(fin),
        [&inner](const std::uint8_t* p, std::size_t n) {
            inner.insert(inner.end(), p, p + n);
        },
        kChunkSize);

    // Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    itb::wrapper::WrapStreamWriter ww{
        itb::wrapper::Cipher::Aes128Ctr,
        outerKey.data(), outerKey.size()};
    ww.update_in_place(inner.data(), inner.size());

    std::ofstream fout("/tmp/64mb.enc", std::ios::binary);
    fout.write(reinterpret_cast<const char*>(ww.nonce().data()),
               static_cast<std::streamsize>(ww.nonce().size()));
    fout.write(reinterpret_cast<const char*>(inner.data()),
               static_cast<std::streamsize>(inner.size()));
}

// Receiver — strip the leading nonce, unwrap the body, feed the
// recovered inner-stream bytes to decrypt_auth.
{
    const std::size_t nlen =
        itb::wrapper::nonce_size(itb::wrapper::Cipher::Aes128Ctr);
    std::ifstream fin("/tmp/64mb.enc", std::ios::binary);
    std::vector<std::uint8_t> wire_nonce(nlen, 0);
    fin.read(reinterpret_cast<char*>(wire_nonce.data()),
             static_cast<std::streamsize>(nlen));
    itb::wrapper::UnwrapStreamReader ur{
        itb::wrapper::Cipher::Aes128Ctr,
        outerKey.data(), outerKey.size(),
        wire_nonce.data(), wire_nonce.size()};

    std::vector<std::uint8_t> inner_recovered;
    {
        std::vector<std::uint8_t> buf(1u << 16);
        while (fin) {
            fin.read(reinterpret_cast<char*>(buf.data()),
                     static_cast<std::streamsize>(buf.size()));
            const auto got = static_cast<std::size_t>(fin.gcount());
            if (got == 0) break;
            ur.update_in_place(buf.data(), got);
            inner_recovered.insert(inner_recovered.end(),
                                   buf.begin(), buf.begin() + got);
        }
    }

    std::size_t pos = 0;
    auto inner_reader = [&](std::uint8_t* dst, std::size_t cap) -> std::size_t {
        const std::size_t take = std::min(cap, inner_recovered.size() - pos);
        std::copy_n(inner_recovered.begin() + static_cast<std::ptrdiff_t>(pos),
                    take, dst);
        pos += take;
        return take;
    };
    std::ofstream fout("/tmp/64mb.dst", std::ios::binary);
    enc.stream_decrypt_auth(inner_reader, make_writer(fout), kChunkSize);
}
```

**Build + run:**

```sh
g++ -std=c++17 -O2 -Wall -o main main.cpp \
    -I <itb>/bindings/c/include \
    -I <itb>/bindings/cpp/include \
    <itb>/bindings/c/build/libitb_c.a \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64 \
    -lpthread -ldl
./main
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Free functions `itb::encrypt_stream_auth` / `itb::decrypt_stream_auth`
take three `itb::Seed` instances plus an `itb::Mac` (32-byte key from
`/dev/urandom`) and stream through the same chunked-AEAD construction.
The same `StreamSource` / `StreamSink` closure shape applies as in Easy
Mode.

```cpp
itb::Seed noise{"areion512", 1024};
itb::Seed data {"areion512", 1024};
itb::Seed start{"areion512", 1024};
auto mac_key = csprng_mac_key();           // 32 bytes from /dev/urandom
itb::Mac mac{"hmac-blake3", mac_key};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

{
    std::vector<std::uint8_t> inner;
    std::ifstream fin("/tmp/64mb.src", std::ios::binary);
    itb::encrypt_stream_auth(
        noise, data, start, mac,
        make_reader(fin),
        [&inner](const std::uint8_t* p, std::size_t n) {
            inner.insert(inner.end(), p, p + n);
        },
        kChunkSize);

    // Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    itb::wrapper::WrapStreamWriter ww{
        itb::wrapper::Cipher::Aes128Ctr,
        outerKey.data(), outerKey.size()};
    ww.update_in_place(inner.data(), inner.size());

    std::ofstream fout("/tmp/64mb.enc", std::ios::binary);
    fout.write(reinterpret_cast<const char*>(ww.nonce().data()),
               static_cast<std::streamsize>(ww.nonce().size()));
    fout.write(reinterpret_cast<const char*>(inner.data()),
               static_cast<std::streamsize>(inner.size()));
}
```

**Build + run:**

```sh
g++ -std=c++17 -O2 -Wall -o main main.cpp \
    -I <itb>/bindings/c/include \
    -I <itb>/bindings/cpp/include \
    <itb>/bindings/c/build/libitb_c.a \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64 \
    -lpthread -ldl
./main
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

Linking pulls in both the static C-binding archive
(`build/libitb_c.a`, used by the C++ wrapper internally) AND the shared
Go-built library (`-litb`). The C++ headers under `bindings/cpp/include`
re-use the C-binding's `itb.h` for the raw ABI declarations.

## Quick Start — `itb::Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

`itb::Encryptor` (mirroring the `github.com/everanium/itb/easy` Go
sub-package) replaces the lower-level `Seed` / `encrypt` / `decrypt`
ceremony with one constructor call: it allocates its own three
(Single) or seven (Triple) seeds plus MAC closure, snapshots the global
configuration into a per-instance Config, and exposes setters that
mutate only its own state. Two encryptors with different settings run
side-by-side without cross-contamination.

The MAC primitive is bound at construction time via the third argument
(`hmac-blake3` — recommended default, `hmac-sha256`, `kmac256`); an
empty `mac` substitutes `"hmac-blake3"`. A fresh 32-byte CSPRNG MAC
key is allocated alongside the per-seed PRF keys, and
`enc.export_state()` carries all of them in one
`std::vector<std::uint8_t>` blob.

```cpp
// Sender

#include <itb.hpp>
#include <iostream>
#include <string>
#include <vector>

// mode = 1 = Single Ouroboros (3 seeds); mode = 3 = Triple (7 seeds).
itb::Encryptor enc{"areion512", 2048, "hmac-blake3", 1};

enc.set_nonce_bits(512);    // default: 128
enc.set_barrier_fill(4);    // CSPRNG fill margin; default: 1, valid: 1, 2, 4, 8, 16, 32
enc.set_bit_soup(1);        // bit-level split ("bit-soup"; default: 0 = byte-level)
enc.set_lock_soup(1);       // Insane Interlocked Mode: per-chunk PRF-keyed
                            // bit-permutation overlay on top of bit-soup
                            // (auto-couples with bit_soup for Single)
enc.set_lock_batch(1);      // Recommended under the PRF assumption,
                            // the performance Lock Soup mode.
                            // Symmetric, set on both sides.

// enc.set_lock_seed(1);    // optional dedicated lockSeed — separates
                            // bit-permutation PRF keying from the
                            // noiseSeed-driven noise channel; adds one
                            // extra seed slot (3 -> 4 / 7 -> 8). Must be
                            // called BEFORE the first encrypt — mid-session
                            // throws STATUS_EASY_LOCKSEED_AFTER_ENCRYPT.

// Persistence blob — seeds + PRF keys + MAC key (and lockSeed).
std::vector<std::uint8_t> blob = enc.export_state();
std::cout << "state blob: " << blob.size() << " bytes\n";

std::string plaintext = "any text or binary data - including 0x00 bytes";

// Authenticated encrypt — 32-byte tag embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
std::vector<std::uint8_t> encrypted = enc.encrypt_auth(plaintext);
std::cout << "encrypted: " << encrypted.size() << " bytes\n";

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = itb::wrapper::wrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    encrypted.data(), encrypted.size());

// Compose the on-wire blob: `nonce || mutated-ciphertext`.
std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
std::copy(nonce.begin(), nonce.end(), wire.begin());
std::copy(encrypted.begin(), encrypted.end(),
          wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

// Send `wire` + `blob` + `outerKey` (out-of-band). The destructor zeroes
// key material at scope exit; enc.close() surfaces release-time errors
// instead of swallowing them.


// Receiver

// Receive on-wire blob + state blob + outerKey (out-of-band).
// std::vector<std::uint8_t> wire     = ...;
// std::vector<std::uint8_t> blob     = ...;
// std::vector<std::uint8_t> outerKey = ...;

// Strip nonce + XOR-decrypt the body in place. body.first / body.second
// is the (pointer, length) view over the recovered ITB ciphertext.
auto body = itb::wrapper::unwrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    wire.data(), wire.size());
std::vector<std::uint8_t> encrypted(body.first, body.first + body.second);

itb::set_max_workers(8);  // 8 cores (default: 0 = all)

// Optional: peek at blob metadata before constructing a matching
// encryptor (useful when multiplexing blobs of different shapes).
itb::PeekedConfig cfg = itb::peek_config(blob);
std::cout << "peek: primitive=" << cfg.primitive
          << " key_bits=" << cfg.key_bits
          << " mode=" << cfg.mode
          << " mac=" << cfg.mac_name << "\n";

itb::Encryptor dec{cfg.primitive, cfg.key_bits, cfg.mac_name, cfg.mode};

// import_state restores nonce_bits / barrier_fill / bit_soup /
// lock_soup and lockSeed from the blob. The set_* calls below are
// pre-import override knobs; barrier_fill is asymmetric — a
// receiver-set value > 1 wins over the blob's value.
dec.set_nonce_bits(512);
dec.set_barrier_fill(4);
dec.set_bit_soup(1);
dec.set_lock_soup(1);
dec.set_lock_batch(1);      // Recommended under the PRF assumption,
                            // the performance Lock Soup mode.
                            // Symmetric, set on both sides.
// dec.set_lock_seed(1);   // optional — import below restores it from the blob.

dec.import_state(blob);

// Authenticated decrypt — single-bit tamper triggers MAC failure
// (no oracle leak). Mismatch surfaces as ItbError with code() ==
// status::kMacFailure, not a corrupted plaintext.
try {
    std::vector<std::uint8_t> recovered = dec.decrypt_auth(encrypted);
    std::string recovered_str(recovered.begin(), recovered.end());
    std::cout << "decrypted: " << recovered_str << "\n";
} catch (const itb::ItbError& e) {
    if (e.code() == itb::status::kMacFailure) {
        std::cout << "MAC verification failed -- tampered or wrong key\n";
    } else {
        throw;
    }
}
```

### Per-encryptor thread-unsafety contract

Each `Encryptor` is single-thread by construction. Cipher methods,
per-instance setters (`set_nonce_bits` / `set_barrier_fill` /
`set_bit_soup` / `set_lock_soup` / `set_lock_batch` / `set_lock_seed` / `set_chunk_size`),
and persistence (`export_state` / `import_state`) all mutate
per-instance state without locking — concurrent use against the same
encryptor requires external synchronisation. Distinct `Encryptor`
values, each owned by one thread, run independently against the libitb
worker pool.

### Output-buffer ownership contract

Each cipher method returns a freshly-allocated
`std::vector<std::uint8_t>` owned by the caller. The encryptor's
internal cache (the libitb FFI write target) is invisible and lives
across calls; what reaches the caller is always a fresh copy. The
cached bytes are zeroed on grow / `close()` / destruction, so residual
ciphertext / plaintext does not linger beyond the next cipher call.

## Quick Start — Mixed primitives (Different PRF per seed slot)

`itb::Encryptor::Mixed` / `Mixed3` accept per-slot primitive names —
the noise / data / start (and optional lockSeed) slots may carry
different PRFs within the same native hash width. The state blob
carries per-slot primitives + PRF keys; the receiver constructs a
matching encryptor with the same arguments and `import_state`s.

```cpp
// Sender

#include <itb.hpp>
#include <iostream>

// Per-slot primitive selection (Single, 3 + 1 slots). Every name
// must share the same native hash width — mixing widths throws
// ItbError(STATUS_SEED_WIDTH_MIX). Triple mirror: Encryptor::Mixed3
// takes seven per-slot names (noise + 3 data + 3 start) + prim_l.
auto enc = itb::Encryptor::Mixed(
    "blake3",         // prim_n: noiseSeed:  BLAKE3
    "blake2s",        // prim_d: dataSeed:   BLAKE2s
    "areion256",      // prim_s: startSeed:  Areion-SoEM-256
    "blake2b256",     // prim_l: dedicated lockSeed (empty for no lockSeed slot)
    1024,             // key_bits
    "hmac-blake3");   // mac

enc.set_nonce_bits(512);
enc.set_barrier_fill(4);
// BitSoup + LockSoup auto-couple from prim_l above; explicit calls
// are unnecessary but harmless.

// Per-slot introspection — enc.primitive() returns "mixed",
// enc.primitive_at(slot) the per-slot name, enc.is_mixed() the
// predicate. Slot order: 0=noise, 1=data, 2=start, 3=lock (Single);
// Triple grows the middle range to 7 slots + lock.
std::cout << "mixed=" << enc.is_mixed()
          << " primitive=" << enc.primitive() << "\n";
for (int i = 0; i < 4; ++i) {
    std::cout << "  slot " << i << ": " << enc.primitive_at(i) << "\n";
}

auto blob = enc.export_state();
std::string plaintext = "mixed-primitive Easy Mode payload";
auto encrypted = enc.encrypt_auth(plaintext);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = itb::wrapper::wrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    encrypted.data(), encrypted.size());

std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
std::copy(nonce.begin(), nonce.end(), wire.begin());
std::copy(encrypted.begin(), encrypted.end(),
          wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));


// Receiver

// Receive on-wire blob + state blob + outerKey (out-of-band).
// std::vector<std::uint8_t> wire     = ...;
// std::vector<std::uint8_t> blob     = ...;
// std::vector<std::uint8_t> outerKey = ...;

auto body = itb::wrapper::unwrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    wire.data(), wire.size());
std::vector<std::uint8_t> encrypted_r(body.first, body.first + body.second);

// Matching mixed encryptor — every per-slot name plus key_bits and
// mac must agree with the sender. import_state validates each
// per-slot primitive; mismatches throw ItbEasyMismatchError with the
// offending JSON field name on .field().
auto dec = itb::Encryptor::Mixed(
    "blake3", "blake2s", "areion256", "blake2b256",
    1024, "hmac-blake3");

dec.import_state(blob);

auto decrypted = dec.decrypt_auth(encrypted_r);
std::string decrypted_str(decrypted.begin(), decrypted.end());
std::cout << "decrypted: " << decrypted_str << "\n";
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×key_bits)) takes seven seeds
(one shared `noiseSeed` plus three `dataSeed` and three `startSeed`),
all wrapped behind one `Encryptor` constructor with `mode = 3`.

```cpp
#include <itb.hpp>
#include <itb/wrapper.hpp>
#include <string>

// mode=3 selects Triple; other arguments behave as in the Single case.
itb::Encryptor enc{"areion512", 2048, "hmac-blake3", 3};

std::string plaintext = "Triple Ouroboros payload";

auto encrypted = enc.encrypt_auth(plaintext);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = itb::wrapper::wrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    encrypted.data(), encrypted.size());

std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
std::copy(nonce.begin(), nonce.end(), wire.begin());
std::copy(encrypted.begin(), encrypted.end(),
          wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

// Receiver: strip nonce + XOR-decrypt body in place.
auto body = itb::wrapper::unwrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    wire.data(), wire.size());
std::vector<std::uint8_t> encrypted_r(body.first, body.first + body.second);

auto decrypted = enc.decrypt_auth(encrypted_r);
// decrypted holds the recovered plaintext bytes.
```

The seven-seed split is internal; on-wire ciphertext shape matches
Single Ouroboros, only the internal payload split / interleave differs.
Mixed-primitive Triple is reachable via `Encryptor::Mixed3`.

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit `itb::Seed` handles for the
noise / data / start trio plus an optional dedicated `Seed` wired in
via `Seed::attach_lock_seed`. Useful when the caller needs full
control over per-slot keying (e.g. PRF material stored in an HSM).

```cpp
// Sender

#include <itb.hpp>
#include <array>
#include <iostream>
#include <string>

// Optional: global configuration (process-wide, atomic).
itb::set_max_workers(8);
itb::set_nonce_bits(512);    // default: 128
itb::set_barrier_fill(4);    // default: 1, valid: 1, 2, 4, 8, 16, 32
itb::set_bit_soup(1);        // bit-level split ("bit-soup"; default: 0)
itb::set_lock_soup(1);       // per-chunk PRF-keyed bit-permutation overlay
                             // (auto-couples with bit_soup for Single)
itb::set_lock_batch(1);      // Recommended under the PRF assumption,
                             // the performance Lock Soup mode.
                             // Symmetric, set on both sides.

// Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
// pre-keys its primitive once at construction.
itb::Seed ns{"areion512", 2048};   // noise
itb::Seed ds{"areion512", 2048};   // data
itb::Seed ss{"areion512", 2048};   // start

// Optional dedicated lockSeed — separates the bit-permutation PRF's
// keying material from the noiseSeed-driven noise-injection channel.
// The bit-permutation overlay must be engaged (set_bit_soup(1) or
// set_lock_soup(1) — both on above) before the first encrypt.
itb::Seed ls{"areion512", 2048};   // lock
ns.attach_lock_seed(ls);

// HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag. Real code pulls
// the key bytes from a CSPRNG (e.g. /dev/urandom); the zero key
// here is for example purposes only.
std::vector<std::uint8_t> mac_key(32, 0);
itb::Mac mac{"hmac-blake3", mac_key};

std::string plaintext = "any text or binary data - including 0x00 bytes";

// Authenticated encrypt — 32-byte tag embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
auto encrypted = itb::encrypt_auth(ns, ds, ss, mac, plaintext);
std::cout << "encrypted: " << encrypted.size() << " bytes\n";

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = itb::wrapper::wrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    encrypted.data(), encrypted.size());

std::vector<std::uint8_t> wire(nonce.size() + encrypted.size());
std::copy(nonce.begin(), nonce.end(), wire.begin());
std::copy(encrypted.begin(), encrypted.end(),
          wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

// Cross-process persistence: itb::Blob512 packs every seed's keys +
// components, lockSeed, and MAC into one JSON blob.
itb::Blob512 blob;
blob.set_key(itb::blob::Slot::Noise, ns.hash_key());
blob.set_components(itb::blob::Slot::Noise, ns.components());
blob.set_key(itb::blob::Slot::Data, ds.hash_key());
blob.set_components(itb::blob::Slot::Data, ds.components());
blob.set_key(itb::blob::Slot::Start, ss.hash_key());
blob.set_components(itb::blob::Slot::Start, ss.components());
blob.set_key(itb::blob::Slot::Lock, ls.hash_key());
blob.set_components(itb::blob::Slot::Lock, ls.components());
blob.set_mac_key(mac_key);
blob.set_mac_name("hmac-blake3");

auto blob_bytes =
    blob.export_blob(itb::blob::LockSeed | itb::blob::Mac);
std::cout << "persistence blob: " << blob_bytes.size() << " bytes\n";

// Send `encrypted` + `blob_bytes`; wrapper destructors zero + release
// every handle at scope exit.


// Receiver

itb::set_max_workers(8);   // deployment knob — not in Blob512

// Receive on-wire blob + blob_bytes + outerKey (out-of-band).
// std::vector<std::uint8_t> wire       = ...;
// std::vector<std::uint8_t> blob_bytes = ...;
// std::vector<std::uint8_t> outerKey   = ...;

// Strip nonce + XOR-decrypt body in place; encrypted_r is a view over
// the recovered ITB ciphertext bytes inside `wire`.
auto body = itb::wrapper::unwrap_in_place(
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    wire.data(), wire.size());
std::vector<std::uint8_t> encrypted(body.first, body.first + body.second);

// import_blob restores per-slot keys + components and applies the
// captured globals via the process-wide setters.
itb::Blob512 restored;
restored.import_blob(blob_bytes);

using itb::blob::Slot;
auto rebuild = [&](Slot s) {
    return itb::Seed::from_components(
        "areion512", restored.get_components(s), restored.get_key(s));
};
auto ns2 = rebuild(Slot::Noise);
auto ds2 = rebuild(Slot::Data);
auto ss2 = rebuild(Slot::Start);
auto ls2 = rebuild(Slot::Lock);
ns2.attach_lock_seed(ls2);

itb::Mac mac2{restored.get_mac_name(), restored.get_mac_key()};

// Authenticated decrypt — single-bit tamper triggers MAC failure
// (no oracle leak).
auto decrypted = itb::decrypt_auth(ns2, ds2, ss2, mac2, encrypted);
std::string decrypted_str(decrypted.begin(), decrypted.end());
std::cout << "decrypted: " << decrypted_str << "\n";
```

## Streams — chunked I/O over caller-owned source / sink callbacks

The push-pattern wrappers (`itb::StreamEncryptor` /
`itb::StreamDecryptor` plus seven-seed `StreamEncryptorTriple` /
`StreamDecryptorTriple`) and the free-function bridges
(`itb::encrypt_stream` / `itb::decrypt_stream` plus Triple variants)
wrap the Single Message Encrypt / Decrypt API behind a chunked I/O surface.
ITB ciphertexts cap at ~64 MB plaintext per chunk; the binding slices
larger inputs, encrypts each chunk through the regular FFI path, and
concatenates the results. Memory peak is bounded by `chunk_size`
(default `kDefaultChunkSize` = 16 MiB); `chunk_size = 0` throws
`ItbError(STATUS_BAD_INPUT)`.

Push wrappers take a `StreamSink`
(`std::function<void(const std::uint8_t*, std::size_t)>`) receiving
each emitted chunk; the caller drives via `write(buf)` / `feed(buf)`
and finally `close()`. The free-function bridges add a `StreamSource`
(`std::function<std::size_t(std::uint8_t*, std::size_t)>`) — read up
to `cap` bytes, return the number actually read (zero on EOF) — and
loop until EOF internally.

```cpp
#include <itb.hpp>
#include <itb/wrapper.hpp>
#include <vector>

itb::Seed n{"blake3", 1024};
itb::Seed d{"blake3", 1024};
itb::Seed s{"blake3", 1024};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
// auto outerKey = itb::wrapper::derive_key(itb::wrapper::Cipher::Aes128Ctr, master);

// Push-pattern: sink receives each ITB chunk. close() flushes the
// trailing partial chunk; destructor best-effort-flushes on scope exit.
std::vector<std::uint8_t> sink;
{
    itb::StreamEncryptor enc{n, d, s,
        [&sink](const std::uint8_t* p, std::size_t len) {
            sink.insert(sink.end(), p, p + len);
        },
        1u << 16};
    enc.write(std::string_view{"chunk one"});
    enc.write(std::string_view{"chunk two"});
    enc.close();
}

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
std::vector<std::uint8_t> wire;
{
    itb::wrapper::WrapStreamWriter ww{
        itb::wrapper::Cipher::Aes128Ctr,
        outerKey.data(), outerKey.size()};
    wire.reserve(ww.nonce().size() + sink.size());
    wire.insert(wire.end(), ww.nonce().begin(), ww.nonce().end());
    auto wrapped = ww.update(sink.data(), sink.size());
    wire.insert(wire.end(), wrapped.begin(), wrapped.end());
}

// Receiver: strip nonce, unwrap body, feed to decrypt.
const std::size_t nlen =
    itb::wrapper::nonce_size(itb::wrapper::Cipher::Aes128Ctr);
itb::wrapper::UnwrapStreamReader ur{
    itb::wrapper::Cipher::Aes128Ctr,
    outerKey.data(), outerKey.size(),
    wire.data(), nlen};
auto ciphertext = ur.update(wire.data() + nlen, wire.size() - nlen);

// Feed-pattern: feed ciphertext bytes at any granularity (partial
// chunks buffered); sink receives each decrypted plaintext. close()
// throws when leftover bytes do not form a complete chunk.
std::vector<std::uint8_t> psink;
{
    itb::StreamDecryptor dec{n, d, s,
        [&psink](const std::uint8_t* p, std::size_t len) {
            psink.insert(psink.end(), p, p + len);
        }};
    dec.feed(ciphertext);
    dec.close();
}
// psink == bytes-of("chunk onechunk two")
```

Switching `itb::set_nonce_bits` mid-stream produces a chunk header
layout the paired decryptor (which snapshots `itb_header_size` at
construction) cannot parse — the nonce size must be stable for the
lifetime of one stream pair.

### Seed-lifetime contract on streams

The stream wrappers cache raw pointers to the supplied `Seed` (and
optional `Mac`) values. Every `Seed` and `Mac` handed to a stream
wrapper MUST remain alive for the entire session — letting any go out
of scope before `close()` / destructor returns is undefined behaviour
(use-after-free in the FFI call). Practical pattern: declare the seeds
in the same scope as the stream and before it, so reverse-order
destruction outlives the stream.

## Native Blob — low-level state persistence

`itb::Blob128` / `Blob256` / `Blob512` are width-typed containers
packing low-level encryptor material (per-seed hash key + components,
optional lockSeed, optional MAC key + name) plus captured process-wide
configuration into one self-describing JSON blob. Used on the
lower-level path where each seed slot may carry a different primitive;
`Encryptor::export_state` is a narrower one-primitive-per-encryptor
view of the same wire format.

Slot identifiers live in `itb::blob::Slot` (`Noise`, `Data`, `Start`,
`Lock`, `Data1`–`Data3`, `Start1`–`Start3`); option flags in the
bitwise `itb::blob::Opt` (`None`, `LockSeed`, `Mac`). Combine flags
with bitwise OR and pass to `export_blob` / `export_triple`.

`export_blob` packs Single, `export_triple` packs Triple; importers
reject the wrong shape with `ItbBlobModeMismatchError`. Globals
(NonceBits / BarrierFill / BitSoup / LockSoup / LockBatch) are captured at export
and applied process-wide on import via `itb::set_*`.

## Hash primitives (Single / Triple)

Single Ouroboros — three seeds (`noiseSeed`, `dataSeed`, `startSeed`)
via `itb::encrypt` / `decrypt` / `encrypt_auth` / `decrypt_auth`.
Triple Ouroboros (3× security: P × 2^(3×key_bits)) — seven seeds (one
shared `noiseSeed`, three `dataSeed`, three `startSeed`) via the
`*_triple` counterparts. Streaming: `StreamEncryptorTriple` /
`StreamDecryptorTriple` / `encrypt_stream_triple` /
`decrypt_stream_triple`.

All seeds in one call must share the same native hash width; mixing
widths throws `ItbError(STATUS_SEED_WIDTH_MIX)`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Threading model

Process-wide setters (`itb::set_nonce_bits`, `set_barrier_fill`,
`set_bit_soup`, `set_lock_soup`, `set_max_workers`) are atomic
(`atomic.Int32.Store`) and safe from any thread in isolation. The
caveat is logical, not atomic — changing any knob while an encrypt /
decrypt call is in flight corrupts the running operation, since the
cipher snapshots its configuration at entry. Treat the globals as
set-once-at-startup; runtime updates need external sequencing against
active cipher calls.

A single `itb::Encryptor` is **not safe** for concurrent use — cipher
methods, per-instance setters, and persistence all mutate per-instance
state without locking. Distinct `Encryptor` handles, each owned by one
thread, run independently against the libitb worker pool.

The low-level free functions (`itb::encrypt` / `itb::decrypt` /
`itb::encrypt_auth` / `itb::decrypt_auth` plus Triple counterparts)
take read-only `Seed` references and allocate output per call — they
are thread-safe under concurrent invocation on the same seeds. Two
exceptions: `Seed::attach_lock_seed` mutates the noise seed and must
not race against an in-flight cipher call on it, and the process-wide
setters above stay process-global.

`itb::last_error()` is captured into thread-local storage on every
failing call. The status code on every raised `ItbError` is unaffected
by thread interleaving.

**Signal-handler reentrance.** No binding entry point is
async-signal-safe — they allocate via `malloc`, mutate per-thread
last-error TLS, and dispatch into libitb's Go worker pool, all
incompatible with `signal-safety(7)`. Post work from a signal handler
to a regular thread (e.g. `eventfd` / pipe-write) and re-enter from
there.

## Persistence

Two complementary surfaces ship:

- **`Encryptor::export_state` / `import_state`.** High-level: one call
  serialises every seed slot, PRF key, MAC key + name, and per-instance
  configuration into a `std::vector<std::uint8_t>` blob. The receiver
  constructs a matching encryptor (same primitive / key_bits / mode /
  mac) and calls `import_state(blob)`. `itb::peek_config(blob)` parses
  metadata (`primitive` / `key_bits` / `mode` / `mac_name`) without
  full validation — useful when multiplexing blobs of different shapes.
- **`Blob128` / `Blob256` / `Blob512`.** Low-level: width-typed Native
  Blob containers — see the section above for the per-slot API.

Both capture process-wide configuration (NonceBits / BarrierFill /
BitSoup / LockSoup) at export. Easy Mode restore applies per-instance;
Native Blob restore applies via the process-wide setters.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt calls
in the process. Out-of-range values throw
`ItbError(STATUS_BAD_INPUT)` rather than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `itb::set_max_workers(n)` | non-negative int | 0 (auto) |
| `itb::set_nonce_bits(n)` | 128, 256, 512 | 128 |
| `itb::set_barrier_fill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `itb::set_bit_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `itb::set_lock_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `itb::set_lock_batch(mode)` | 0 (off), non-zero (on) | 0 |

Read-only accessors: `itb::max_key_bits()`, `itb::channels()`,
`itb::header_size()`, `itb::version()`. Each setter has a paired
`itb::get_*` getter.

For custom file formats around ITB chunks:
`itb::parse_chunk_len(header, len)` inspects the fixed-size chunk
header and returns the chunk's on-the-wire length;
`itb::header_size()` returns the active header byte count (20 / 36 /
68 for nonce sizes 128 / 256 / 512 bits).

`itb::list_hashes()` returns `std::vector<HashEntry>` (`name` /
`width`); `itb::list_macs()` returns `std::vector<MacEntry>` (`name`
/ `key_size` / `tag_size` / `min_key_bytes`). Shipping MACs:
`kmac256`, `hmac-sha256`, `hmac-blake3`.

See **Threading model** above for the set-once-at-startup discipline
these setters require.

## Error handling

Every non-OK libitb status surfaces as a typed exception derived from
`itb::ItbError`, carrying the structural status code (`code()`) and
the textual diagnostic (`message()`):

```cpp
#include <itb.hpp>
#include <iostream>

std::vector<std::uint8_t> keybuf(32, 0);
try {
    itb::Mac bad{"nonsense", keybuf};
} catch (const itb::ItbError& e) {
    // e.code() == itb::status::kBadMac
    std::cerr << "code=" << e.code()
              << " name=" << e.name()
              << " msg=" << e.message() << "\n";
}
```

The typed-exception hierarchy:

- **`ItbError`** — base class; `int code()`, `std::string_view
  message()`, `std::string_view name()`, formatted `what()`.
- **`ItbEasyMismatchError`** — `STATUS_EASY_MISMATCH`; adds
  `std::string_view field()` with the offending JSON field name from a
  failed `Encryptor::import_state`.
- **`ItbBlobModeMismatchError`** — `STATUS_BLOB_MODE_MISMATCH`; Native
  Blob importer receives a Single blob into a Triple receiver (or vice
  versa).
- **`ItbBlobMalformedError`** — `STATUS_BLOB_MALFORMED`; JSON parse,
  magic / shape failure, or a too-new version surfaced via
  `peek_config` (which conflates version-too-new with malformed).
- **`ItbBlobVersionTooNewError`** — `STATUS_BLOB_VERSION_TOO_NEW`;
  `import_blob` differentiates version-too-new from `Malformed`.

Two free functions expose the per-thread libitb diagnostic surface
independently of the exception path:

- **`itb::last_error()`** — textual diagnostic from the most recent
  non-OK call on the calling thread (empty string when none).
- **`itb::last_mismatch_field()`** — `std::optional<std::string>` with
  the offending JSON field name from the most recent
  `STATUS_EASY_MISMATCH`. The same value reaches
  `ItbEasyMismatchError::field()`; this free function is for callers
  needing it outside try / catch.

Status-code constants in `itb::status::k*` map bit-identically to the
C binding's `ITB_*` enum; `itb::status::name(code)` returns a stable
textual name. Empty plaintext / ciphertext is rejected with
`STATUS_ENCRYPT_FAILED` ("itb: empty data") — pass at least one byte.

### Status codes

The 26 `ITB_*` constants are mirrored bit-identically as
`itb::status::k*` constexpr ints in `<itb/errors.hpp>`.

| Code | Constant | C++ mirror | Path | Typed exception |
|---|---|---|---|---|
| 0 | `ITB_OK` | `itb::status::kOk` | success | (no throw) |
| 1 | `ITB_BAD_HASH` | `itb::status::kBadHash` | cold | `ItbError` |
| 2 | `ITB_BAD_KEY_BITS` | `itb::status::kBadKeyBits` | cold | `ItbError` |
| 3 | `ITB_BAD_HANDLE` | `itb::status::kBadHandle` | cold | `ItbError` |
| 4 | `ITB_BAD_INPUT` | `itb::status::kBadInput` | cold | `ItbError` |
| 5 | `ITB_BUFFER_TOO_SMALL` | `itb::status::kBufferTooSmall` | cold | `ItbError` |
| 6 | `ITB_ENCRYPT_FAILED` | `itb::status::kEncryptFailed` | cold | `ItbError` |
| 7 | `ITB_DECRYPT_FAILED` | `itb::status::kDecryptFailed` | cold | `ItbError` |
| 8 | `ITB_SEED_WIDTH_MIX` | `itb::status::kSeedWidthMix` | cold | `ItbError` |
| 9 | `ITB_BAD_MAC` | `itb::status::kBadMac` | cold | `ItbError` |
| 10 | `ITB_MAC_FAILURE` | `itb::status::kMacFailure` | warm | `ItbError` |
| 11 | `ITB_EASY_CLOSED` | `itb::status::kEasyClosed` | cold | `ItbError` |
| 12 | `ITB_EASY_MALFORMED` | `itb::status::kEasyMalformed` | cold | `ItbError` |
| 13 | `ITB_EASY_VERSION_TOO_NEW` | `itb::status::kEasyVersionTooNew` | cold | `ItbError` |
| 14 | `ITB_EASY_UNKNOWN_PRIMITIVE` | `itb::status::kEasyUnknownPrimitive` | cold | `ItbError` |
| 15 | `ITB_EASY_UNKNOWN_MAC` | `itb::status::kEasyUnknownMac` | cold | `ItbError` |
| 16 | `ITB_EASY_BAD_KEY_BITS` | `itb::status::kEasyBadKeyBits` | cold | `ItbError` |
| 17 | `ITB_EASY_MISMATCH` | `itb::status::kEasyMismatch` | warm | `ItbEasyMismatchError` |
| 18 | `ITB_EASY_LOCKSEED_AFTER_ENCRYPT` | `itb::status::kEasyLockSeedAfterEncrypt` | cold | `ItbError` |
| 19 | `ITB_BLOB_MODE_MISMATCH` | `itb::status::kBlobModeMismatch` | warm | `ItbBlobModeMismatchError` |
| 20 | `ITB_BLOB_MALFORMED` | `itb::status::kBlobMalformed` | warm | `ItbBlobMalformedError` |
| 21 | `ITB_BLOB_VERSION_TOO_NEW` | `itb::status::kBlobVersionTooNew` | warm | `ItbBlobVersionTooNewError` |
| 22 | `ITB_BLOB_TOO_MANY_OPTS` | `itb::status::kBlobTooManyOpts` | cold | `ItbError` |
| 23 | `ITB_STREAM_TRUNCATED` | `itb::status::kStreamTruncated` | warm | `ItbStreamTruncatedError` |
| 24 | `ITB_STREAM_AFTER_FINAL` | `itb::status::kStreamAfterFinal` | warm | `ItbStreamAfterFinalError` |
| 99 | `ITB_INTERNAL` | `itb::status::kInternal` | cold | `ItbError` |

Warm-path codes — MAC failure on tampered ciphertext, Easy Mode blob
mismatch, Native Blob import-side discriminators — are typically
caught as their typed subclass. Cold-path codes (programmer errors,
malformed input, internal sentinels) are usually caught generically as
`ItbError`.

## Constraints

- **C++17 minimum.** Headers use `std::string_view`, `std::optional`,
  structured bindings, `if constexpr`, and inline variables. GCC ≥ 9
  and Clang ≥ 9 meet the baseline.
- **Header-only.** Consumer-visible declarations live in
  `include/itb/*.hpp` (plus the synced `include/itb.h` C-ABI header);
  no archive or shared library is produced for the C++ surface itself.
- **Underlying static archive + libitb.so required.** Links
  transitively against `bindings/c/build/libitb_c.a` and
  `dist/<os>-<arch>/libitb.<ext>` — both must be built first.
- **No external runtime deps beyond libc++ + libitb.so.** The test
  runner additionally requires Catch2 v3.
- **Frozen C ABI.** The `ITB_*` exports in `include/itb.h` (synced
  from the C binding) are the contract; the binding does not extend
  or reshape them.
- **No `dlopen`.** Symbols are bound at link time. Consumers wanting
  runtime FFI loading can wrap this binding in their own `dlopen`
  shim.

## API Overview

| Header | Public surface |
|---|---|
| `<itb.hpp>` | Meta-header — pulls in every wrapper below |
| `<itb/errors.hpp>` | `ItbError` base + four typed subclasses; `itb::status::*`; `last_error()` / `last_mismatch_field()` |
| `<itb/library.hpp>` | Process-wide setters / getters, `list_hashes` / `list_macs`, `version()`, `header_size()`, `parse_chunk_len()` |
| `<itb/seed.hpp>` | `itb::Seed` — RAII over `itb_seed_t`; CSPRNG and `from_components` constructors; `width()` / `hash_key()` / `components()` / `attach_lock_seed()` |
| `<itb/mac.hpp>` | `itb::Mac` — RAII over `itb_mac_t`; `(name, key)` constructor |
| `<itb/cipher.hpp>` | Free-function low-level entry points — `encrypt` / `decrypt` / `encrypt_auth` / `decrypt_auth` plus Triple counterparts |
| `<itb/encryptor.hpp>` | `itb::Encryptor` — Easy Mode RAII; single-primitive constructor + `Mixed` / `Mixed3`; cipher methods, per-instance setters, persistence; `peek_config` |
| `<itb/streams.hpp>` | `StreamEncryptor` / `StreamDecryptor` push + Triple variants; free-function bridges `encrypt_stream` / `decrypt_stream`; `kDefaultChunkSize` |
| `<itb/blob.hpp>` | `Blob128` / `Blob256` / `Blob512` Native Blob wrappers; `blob::Slot` / `blob::Opt` |

All public types live in the top-level `itb::` namespace; helpers
between headers live in `itb::detail::`. The `itb::status::*` constants
and the `itb::blob::Slot` / `itb::blob::Opt` enums are namespaced for
collision-free use. Hash names via `itb::list_hashes()`; MAC names
(`kmac256`, `hmac-sha256`, `hmac-blake3`) via `itb::list_macs()`.

### Go runtime tuning setters

Two additional process-wide setters from `<itb/library.hpp>` configure
the Go runtime inside libitb. Both functions return the previous value
and accept a negative argument as a "query only, do not change"
sentinel.

| Function | Purpose |
|---|---|
| `std::int64_t itb::set_memory_limit(std::int64_t limit)` | Sets the Go runtime heap soft limit in bytes. Overrides the `ITB_GOMEMLIMIT` env var sourced at library load. |
| `int itb::set_gc_percent(int pct)` | Sets the Go GC trigger percentage (default 100). Overrides the `ITB_GOGC` env var sourced at library load. |

### Wrapper (`itb::wrapper`)

Header-only RAII surface in `<itb/wrapper.hpp>`.

| Symbol | Purpose |
|---|---|
| `wrapper::Cipher::Areion256 / Areion512 / Blake2b256 / Blake2b512 / Blake2s / Blake3 / Aes128Ctr / SipHash24 / ChaCha20 / etc...` | Cipher enum |
| `wrapper::ffi_name(cipher)` | Canonical cipher name |
| `wrapper::key_size(cipher) / wrapper::nonce_size(cipher)` | Cipher dimension accessors |
| `wrapper::generate_key(cipher) -> std::vector<std::uint8_t>` | CSPRNG-fresh wrapper key |
| `wrapper::derive_key(cipher, master, master_len) -> std::vector<std::uint8_t>` | Deterministic wrapper key from a master secret (>= 32 bytes, e.g. an ML-KEM shared secret) |
| `wrapper::wrap(cipher, key, key_len, blob, blob_len)` / `wrapper::unwrap(cipher, key, key_len, wire, wire_len)` | Single Message Wrap / Unwrap |
| `wrapper::wrap_in_place(cipher, key, key_len, blob, blob_len)` / `wrapper::unwrap_in_place(cipher, key, key_len, wire, wire_len)` | In-place Wrap / Unwrap |
| `wrapper::WrapStreamWriter(cipher, key, key_len)` / `wrapper::UnwrapStreamReader(cipher, key, key_len, wire_nonce, wire_nonce_len)` | Streaming wrap writer / unwrap reader |
| `ItbError` (with `STATUS_BAD_INPUT` / `STATUS_BAD_HANDLE`) | Typed errors |
