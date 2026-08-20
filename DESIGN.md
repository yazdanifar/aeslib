# Design

Architecture and reasoning behind the key decisions in this library.

## Layout

```
include/aeslib/       public API headers
  aes256_ctr.hpp       Aes256Ctr — the encrypt/decrypt entry point
  key.hpp              SecretKey — RAII key holder
  backend.hpp          Backend enum + active_backend() query
  container.hpp        on-disk ciphertext container + file I/O helpers
  exceptions.hpp        IoError / FormatError
src/                   implementation
  aes256_ctr.cpp        CTR-mode driver: builds counter blocks, dispatches
                         to a backend, XORs the keystream
  aes_core_soft.cpp      portable AES-256 forward cipher (FIPS-197), no
                         intrinsics, used as the fallback
  aes_core_ni.cpp        AES-256 forward cipher using AES-NI intrinsics,
                         used when the CPU supports it
  cpu_detect.cpp          runtime CPUID check
  csprng.cpp              OS CSPRNG wrapper
  key.cpp, container.cpp  key/container (de)serialization and file I/O
  internal.hpp             shared declarations, not part of the public API
main.cpp                end-to-end harness (see README.md)
```

## Hardware/software dispatch

`aeslib::active_backend()` runs a CPUID check (`CPUID.1:ECX.AESNI`, bit 25)
the first time it's called and memoizes the result in a function-local
static — so the decision is made once, at runtime, on whatever machine the
binary happens to be running on. It is never baked in via `#ifdef __AES__`
or `-march=native`; the same compiled binary takes the hardware path on an
AES-NI-capable host and the software path on one without, which is what lets
one binary be correct on both. `Aes256Ctr` calls `active_backend()`
internally to pick which block-encrypt function to call; callers of the
public API never see this decision, but it's exposed as a free function so
tests/diagnostics can observe (and the `main.cpp` harness prints) which path
actually ran.

The AES-NI code lives in its own translation unit (`aes_core_ni.cpp`) and is
the *only* file compiled with `-maes` on GCC/Clang (see `CMakeLists.txt`);
every other file — including the CTR driver that calls into it — stays
free of any architecture-specific instruction set flags. That's what makes
it safe to ship as one portable binary: the compiler never emits an AES-NI
instruction outside that one file, and that file is only ever *called* after
`cpu::has_aes_ni()` has confirmed the instructions are safe to execute.

Because CTR mode only ever needs the forward AES transform (see below),
both backends implement encryption only — there is no AES decryption
routine anywhere in this codebase.

### How both dispatch outcomes were actually exercised

2.2 requires that the *same binary* be correct on a machine with AES-NI and
one without. Both were exercised, from the same source tree and the same
`CMakeLists.txt`, with no forced-path override:

1. **No AES-NI available** — the ordinary native build on the arm64
   development machine (Apple Silicon). `cpu::has_aes_ni()` is hardcoded to
   `false` on non-x86 targets (`AESLIB_X86` is never defined there, see
   `cpu_detect.cpp`), so this is a real "hardware unavailable" case, not a
   simulated one. `active_backend()` reported `Software`, and the harness
   round-tripped correctly.
2. **AES-NI available** — the same source built inside an x86_64 Linux
   container (`docker run --platform linux/amd64 gcc:13 ...`). Docker
   Desktop on Apple Silicon registers QEMU's `qemu-x86_64-static` as a
   `binfmt_misc` handler for foreign ELF binaries, so every x86_64
   instruction in the container — including the
   `aeskeygenassist`/`aesenc`/`aesenclast` opcodes `aes_core_ni.cpp` emits —
   is dynamically translated (QEMU TCG) to run on the host CPU. The emulated
   CPUID reports AES-NI support, so `active_backend()` reported `Hardware`,
   and the harness round-tripped correctly there too.

A standalone known-answer test (FIPS-197 Appendix C.3, AES-256) was also run
directly against `aes256_encrypt_block_ni()` and `aes256_encrypt_block_soft()`,
confirming both produce the exact published ciphertext block for the same
key/plaintext — i.e. the two backends don't just each "work", they agree
with each other and with the published test vector.

Note that case 2 relies on real instruction-set emulation (QEMU TCG), not a
stub — but it's still emulation, not physical AES-NI hardware. No Docker
setup is required (or provided) to build or run the library itself; this was
purely a development-time verification step, documented here for
transparency about what "tested on both paths" actually means for this
submission.

### Why not just use a general crypto library for the software path

For a small challenge submission, pulling in OpenSSL/libsodium/mbedTLS
purely to get software AES would trade a very well-specified, well-tested
80 lines of textbook Rijndael for a much larger, harder-to-audit dependency
and a more fragile cross-platform build (`FetchContent`/`find_package`
version pinning, ABI shims for MSVC, etc.). AES-256 encryption is
completely specified by FIPS-197 and validated here against the official
Appendix C.3 known-answer test, so writing it directly keeps the library
dependency-free and easy for a reviewer to audit end-to-end. This is a
one-way call: it is *not* a recommendation to hand-roll crypto in a real
production system with a real threat model and real key-management
requirements — there, a vetted, actively-maintained library is almost
always the right choice specifically because of the ongoing side-channel
and implementation-bug hardening that a bespoke implementation doesn't get
for free.

## Nonce/IV strategy

Each `Aes256Ctr::encrypt()` call generates a fresh 96-bit nonce from the OS
CSPRNG and combines it with a 32-bit big-endian block counter (starting at
0) to form the 128-bit CTR input block — the same nonce||counter
construction used by AES-GCM. The nonce is stored alongside the ciphertext
in the container (see below); the counter is never stored, since it's
implicit in a block's position in the stream.

This means correctness only depends on the pair (key, nonce) never
repeating. Because the nonce is randomly generated per encryption rather
than tracked as a counter across the key's lifetime, the birthday bound
applies: for a given key, the probability of a nonce collision becomes
non-negligible only after roughly 2^48 encryptions under that key (birthday
bound on a 96-bit space) — far beyond what a single key in this library is
expected to encrypt. A production system doing extremely high-volume
encryption under one long-lived key would want a stateful (counter-based,
not random) nonce instead; that tradeoff didn't seem worth the added
complexity (persisting nonce-counter state across process restarts) for
this library's scope.

The 32-bit counter caps a single message at 2^32 blocks (64 GiB) before the
counter would wrap and start reusing keystream within that one message;
not a concern for the sizes this library is meant for.

## On-disk container format

Key and ciphertext are always written to **separate files** — the
container never carries key material, so leaking one file doesn't leak
plaintext without also having the other.

Ciphertext container (`.aesc`), all integers little-endian:

| bytes | field      | meaning                              |
|-------|------------|---------------------------------------|
| 0–3   | magic      | ASCII `"AESC"`                        |
| 4     | version    | format version, currently `1`         |
| 5–16  | nonce      | 12-byte CTR nonce                     |
| 17–24 | ct_len     | `uint64_t`, ciphertext length in bytes|
| 25–   | ciphertext | `ct_len` bytes                        |

Key file: `version (1 byte)` + `32` raw key bytes, written with `0600`
permissions on POSIX.

Both formats carry an explicit version byte specifically so a future format
change (e.g. switching to an AEAD mode and adding an authentication tag, or
a different nonce size) can be introduced without breaking the ability to
read files written by an older version of the library — a reader can
branch on the version byte before interpreting the rest of the layout.

## Key handling

`SecretKey` is move-only (copying is disabled at the type level, so a key
can't be accidentally duplicated) and zeroes its backing buffer on
destruction and on move-from. The wipe loop uses a `volatile` reference to
prevent the compiler from treating it as a dead store and optimizing it
away, since the buffer's contents in memory aren't otherwise observed
again. This is a minimal hygiene step, not the full "keep raw key
material out of general-purpose memory" bonus objective (no `mlock`,
no OS keystore integration, no KDF-wrapped storage) — those are called out
in the challenge brief as separate, optional bonus work this submission
doesn't attempt.

## Randomness

Keys and nonces are generated via the OS's native CSPRNG (`BCryptGenRandom`
on Windows, `getrandom(2)` on Linux, `arc4random_buf` elsewhere) — never
`rand()`, `std::mt19937`, or any other non-cryptographic PRNG.

## Error handling

Two exception types (`aeslib::IoError`, `aeslib::FormatError`) cover
filesystem/OS failures and malformed container/key files respectively.
Nothing in the public API uses output-parameter error codes.

## Third architecture (not implemented, but why it'd be straightforward)

The dispatch model deliberately isolates *all* architecture-specific code
behind one interface: two functions with an identical signature
(`Block aes256_encrypt_block_*(const SecretKey&, const Block&)`) plus a
one-function CPU-capability check. Adding ARM AArch64 Crypto Extensions
support (or a third architecture) would mean adding one more
`aes_core_*.cpp` file implementing that same function signature with the
target's intrinsics, extending `cpu_detect.cpp`'s capability check for that
architecture, and adding one more arm to `active_backend()`'s dispatch — no
changes anywhere else in the library, since `Aes256Ctr` only ever calls
through the shared function signature and never branches on architecture
itself.
