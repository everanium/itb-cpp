# ITB C++ Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). C++20 static (`libitb_cpp.a`) + shared
(`libitb_cpp.so`) library that **links against `libitb.so` at compile
time** (`-litb_cpp -litb` with an embedded RPATH) — no runtime symbol
loading. Every hash-name / MAC-name / cipher-name / profile-name is an
opaque `std::string` passed through to Go for validation; the binding
carries no ITB construction logic. The public surface is one
RAII-managed `itb::Pipeline` (init / load / save / rekey / close, Single
Message encrypt / decrypt, whole-buffer stream pumps, incremental
`itb::EncryptStream` / `itb::DecryptStream` sessions with write / end /
read), an `itb::Opts` query-string builder, `itb::register_profile`,
and the Go runtime knobs. Every fallible entry throws `itb::Error`
carrying the numeric `itb::Status` plus the Go-side diagnostic.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make
```

Generic Linux: a Go toolchain, a C++20 compiler (gcc or clang), and
GNU make. macOS: the same via Xcode command-line tools; libitb builds
as `libitb.dylib`. Windows: MinGW-w64 or clang against `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so`, the C++ library, and every
test binary in one step:

```bash
./bindings/cpp/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/cpp && make all
```

## Add to a C++ project

Compile against the public header and link the static archive plus
the underlying `libitb.so` (the generated `libitb.h` sits next to
`libitb.so` in the dist directory):

```bash
c++ -std=c++20 -I/path/to/bindings/cpp/include \
    -isystem /path/to/dist/linux-amd64 myapp.cpp \
    /path/to/bindings/cpp/build/libitb_cpp.a \
    -L/path/to/dist/linux-amd64 -Wl,-rpath,/path/to/dist/linux-amd64 \
    -litb
```

## Usage example

```cpp
#include <itb.hpp>

itb::Pipeline sender = itb::Pipeline::init("singlemsg-triple-mac-v1");
itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(sender.save()));

std::vector<std::uint8_t> wire =
    sender.encrypt_message(itb::as_bytes("data"));
std::vector<std::uint8_t> plain =
    receiver.decrypt_message(itb::as_bytes(wire));
// throws itb::Error on any non-OK status
```

The `itb::Opts` builder overrides the profile default at init (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette, worker cap); every setter goes through `set(key, value)`.
The resolved shape travels inside the blob, so the receiver needs no
options of its own:

```cpp
itb::Opts opts;
opts.set("chunkSize", "65536").set("withWrapper", "false").set("maxWorkers", "4");
itb::Pipeline sender =
    itb::Pipeline::init("singlemsg-triple-mac-v1", opts);
itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(sender.save()));
```

`Pipeline::rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```cpp
std::array<std::byte, 32> perm{}, wrap{};
perm.fill(std::byte{0x11}); wrap.fill(std::byte{0x22});
std::vector<std::uint8_t> rotated = sender.rekey(perm, wrap);
itb::Pipeline receiver2 = itb::Pipeline::load(itb::as_bytes(rotated));
```

The same rotation is available on the receiver side as a master
override pair on load: `itb::Pipeline::load(blob, perm, wrap)`
reopens the blob with fresh masters folded in.

`encrypt_stream_one_shot` / `decrypt_stream_one_shot` put a whole
in-memory payload through the stream chain in a single call. For
bounded-memory streaming, `encrypt_stream_pump` /
`decrypt_stream_pump` move a whole buffer through an incremental
session; the explicit `encrypt_stream_begin` / `decrypt_stream_begin`
sessions expose `write` / `end` / `read` for caller-driven loops.
Byte inputs cross the API as `std::span<const std::byte>`; the
`itb::as_bytes` adaptors build such views over `std::vector`,
`std::span<const std::uint8_t>`, and `std::string_view` carriers.

Allocation-sensitive callers use the reusable-buffer variants:
`encrypt_message_into` / `decrypt_message_into`,
`encrypt_stream_one_shot_into` / `decrypt_stream_one_shot_into`, and
`encrypt_stream_pump_into` / `decrypt_stream_pump_into` write into a
caller-owned `std::span<std::byte>` (sized via
`itb::out_bound(payload)`, adapted from a `std::vector` via
`itb::as_writable_bytes`) and return the byte count written — one
buffer allocated once and rewritten in place across calls, no
per-call allocation or trim copy. The vector-returning entries above
remain the convenience surface.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a thrown `itb::Error` whose
`what()` carries the Go diagnostic.

## Persisting sessions

The blob returned by `save` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `load` reconstructs a Pipeline from it
without naming a profile.

```cpp
std::vector<std::uint8_t> blob = sender.save();               // current blob bytes
itb::Pipeline receiver = itb::Pipeline::load(itb::as_bytes(blob)); // reopen from bytes
sender.save_f("session.blob");                                // write to a file (mode 0600)
itb::Pipeline receiver2 = itb::Pipeline::load_f("session.blob"); // reopen from a file
std::string profile = itb::inspect(itb::as_bytes(blob));      // profile record, no Pipeline
// profile: {"name":"singlemsg-triple-mac-v1","mode":"singlemsg-mac",...}
```

`itb::inspect` decodes the embedded profile record (a JSON object)
without constructing a Pipeline. `save_f` / `load_f` perform the file
access inside libitb.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding throws `itb::Error` with
`itb::Status::RecipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after `load`:

```cpp
receiver.max_workers(4);   // clamped by libitb; <= 0 selects auto
```

## Profile registry

`itb::register_profile` installs a user-defined profile under a new
name from a profile JSON record (the name `register` is a C++
keyword); `itb::lookup` reads a registered record back; `itb::profiles`
lists every registered name as a JSON array. The record's field rules
are enforced by libitb; the binding treats the JSON as an opaque
string.

```cpp
itb::register_profile("my-nomac-plain",
    R"({"mode":"singlemsg-nomac","width":512,"hash":"areion512",)"
    R"("keybits":1024,"wrapper":false,"parallax":false})");
std::string record = itb::lookup("my-nomac-plain");   // record with "name" filled in
std::string names = itb::profiles();                  // ["blob-triple-mac-v1", ...]
```

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```cpp
itb::set_memory_limit(512LL << 20); // 512 MiB soft cap
itb::set_gc_percent(20);            // aggressive GC
```

## Testing

```bash
./bindings/cpp/run_tests.sh
```

The harness builds `libitb.so` + the C++ library, compiles every
`tests/test_*.cpp` to its own standalone executable under
`tests/build/`, and runs each in turn; per-process isolation gives
every test a fresh libitb global state. The suite covers Single
Message round trips per shipped profile, stream pumps, incremental
sessions with pathological batch sizes, tampered-wire failure
stickiness, mid-flight cancellation, rekey, profile registration, and
error mapping — surface parity checks; the deep suite lives in Go
under the shipped tree. Override the compiler via
`CXX=clang++ ./bindings/cpp/run_tests.sh`.

## Sanitizer runs

```bash
cd bindings/cpp
make test-asan       # test suite under AddressSanitizer
make test-ubsan      # test suite under UndefinedBehaviorSanitizer
make test-valgrind   # test suite under valgrind --leak-check=full
```

The sanitizer targets rebuild the library + tests into separate
build directories (`build/asan`, `build/ubsan`) so instrumented and
plain objects never mix. `test-valgrind` requires valgrind to be able
to read the host `ld.so` symbols (on some distributions this needs
the glibc debug-symbol package). `tests/valgrind.supp` silences
memcheck noise whose faulting frame lies inside `libitb.so` — the Go
runtime manages its own stacks and heap in ways memcheck cannot
model; errors in the binding's own C++ frames are never suppressed.

## Benchmarking

```bash
./bindings/cpp/run_bench.sh
```

Micro-benches: `message` (`encrypt_message_into`) and `stream_pump`
(`encrypt_stream_pump_into`) throughput at 1 MiB / 16 MiB / 64 MiB,
reported as an MB/s table on stdout. Each size case drives the
reusable-buffer entry with one scratch buffer sized to the expansion
bound, so the measurement excludes per-iteration allocation churn. The runner exports `ITB_GOMEMLIMIT=512MiB`
+ `ITB_GOGC=20` defaults (respecting caller overrides) and the bench
binaries apply the same caps programmatically.

## eitb utility

A small CLI under `bindings/cpp/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/cpp/eitb && make
./eitb version
./eitb profiles
./eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
./eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

`decrypt` reopens the session with `Pipeline::load` from the blob
hex; the profile argument only selects the Single Message or
streaming cipher pair.

## itb3 CLI

The shipped `itb3` binary under `cmd/itb3/` of the main repository
generates profile files (`.json` on disk) that this binding reopens
via `Pipeline::load_f`; the same utility also encrypts and decrypts
files directly. See `cmd/itb3/README.md` for full usage.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb::last_error()` text is process-global last-write-wins on
  the Go side; `itb::Error` snapshots it at throw time, and the
  status code is always attributable.
- `Pipeline::rekey` must not run concurrently with cipher calls or
  open stream sessions on the same Pipeline.
- A stream session must not outlive its Pipeline; both are move-only
  and release their Go-side handle exactly once via RAII.
