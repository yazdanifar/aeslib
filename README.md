# aeslib

A small C++17 library implementing AES-256-CTR and AES-GCM (AES-128 or
AES-256) encryption/decryption with runtime dispatch between a hardware path
(AES-NI on amd64, ARM AArch64 Crypto Extensions on arm64) and a portable
software fallback, plus a minimal versioned container format for storing
encrypted data separately from its key.

See [DESIGN.md](DESIGN.md) for the architecture, the hardware/software
dispatch mechanism, the on-disk container formats, and the nonce strategy.

## What it does

- `aeslib::SecretKey::generate()` / `generate(KeySize::Aes128)` — generates
  a 256-bit (default) or 128-bit key via the OS CSPRNG.
- `aeslib::Aes256Ctr::encrypt(key, plaintext)` /
  `aeslib::Aes256Ctr::decrypt(key, container)` — unauthenticated AES-256-CTR,
  operating on `std::vector<std::byte>`.
- `aeslib::AesGcm::encrypt(key, plaintext, aad)` /
  `aeslib::AesGcm::decrypt(key, container, aad)` — authenticated AES-GCM
  (AES-128 or AES-256, dispatched on the key's size), with optional
  additional authenticated data.
- Template overloads of `encrypt` / `decrypt_as<T>` on both `Aes256Ctr` and
  `AesGcm` — the `std::vector<std::byte>` path above stays the baseline, but
  any byte-viewable `T` (a contiguous container of trivially copyable
  elements — `std::vector<uint8_t>`, `std::array<X,N>`, `std::string`, ... —
  or a single trivially copyable object, e.g. a plain struct) also works.
- `aeslib::save_container` / `load_container` (CTR) and
  `aeslib::save_gcm_container` / `load_gcm_container` (GCM), plus
  `SecretKey::save_to_file` / `load_from_file` — persist ciphertext and key
  to **separate** files.
- `aeslib::active_backend()` — reports whether the hardware (AES-NI on
  amd64, ARM Crypto Extensions on arm64) or software AES path is in use on
  the current machine.
- `include/aeslib/capi.h` / the `aeslib_c` shared library — a C-compatible
  ABI (opaque handles, status codes, no exceptions crossing the boundary)
  covering key generation, AES-256-CTR, and AES-GCM, for calling the
  library from another language. See "Foreign-language interface" below.

## Build instructions

Requires CMake ≥ 3.16 and a C++17 compiler.

### Linux

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Tested with GCC and Clang.

### Windows

Using Visual Studio's "Developer Command Prompt" (MSVC) or a clang-cl
environment:

```bat
cmake -B build
cmake --build build --config Release
```

The generated executable is at `build\Release\aes_harness.exe` (or
`build\aes_harness.exe` for single-config generators like Ninja).

No external dependencies are fetched by the build — the software AES
fallback and the CSPRNG are both implemented directly against the standard
library and OS APIs (`BCryptGenRandom` on Windows, `getrandom(2)` on
Linux), so there is nothing else to install.

## Running the test harness

```sh
./build/aes_harness      # Linux
build\Release\aes_harness.exe   # Windows
```

This generates a sample plaintext file (if one doesn't already exist),
generates a key, encrypts the plaintext, writes the ciphertext and key to
separate files, reloads both from disk, decrypts, and verifies the
round-tripped plaintext matches the original. It prints which backend
(hardware or software) was used and reports success/failure.

## Unit tests

A CTest-based suite lives under `tests/`, using a small hand-rolled
assertion header (`tests/test_support.hpp`) rather than a third-party
framework — this keeps the whole project, tests included, free of external
dependencies. Build with tests enabled (the default) and run:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Eight suites are registered:

- **`aeslib.aes_core`** — independent AES-256/AES-128 known-answer tests
  (FIPS-197 Appendix C.3/C.1, NIST SP 800-38A F.1.5, two NIST CAVP
  all-zero/all-ones edge cases) against both backends, plus an exhaustive
  check of the software backend's constant-time S-box against the
  canonical 256-entry table (see DESIGN.md's
  [Constant-time software S-box](DESIGN.md#constant-time-software-s-box)).
- **`aeslib.ctr`** — round-trips at a range of sizes (including
  partial-final-block cases), correct counter increment across multiple
  blocks, a boundary test for the 32-bit block-counter guard, CTR's
  expected bit-flip malleability, and nonce freshness.
- **`aeslib.container`** / **`aeslib.key`** — file-format edge cases (bad
  magic, unsupported version, truncated/mismatched-length data).
- **`aeslib.key_storage`** — known-answer tests for the from-scratch
  SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231), and PBKDF2-HMAC-SHA256
  (RFC 7914) primitives, plus passphrase-protected key file round-trip,
  wrong-passphrase, tamper-detection, and iteration-count-validation tests
  (see DESIGN.md's [Safer key storage](DESIGN.md#safer-key-storage)).
- **`aeslib.backend`** — a CI hook for asserting which dispatch path is
  active (`tests/test_backend.cpp`, see the CI section below).
- **`aeslib.reference_vectors`** — seven AES-256-CTR ciphertexts
  cross-checked against an independent implementation (Python's
  `cryptography` library, itself cross-verified against the `openssl`
  CLI — see `tests/test_reference_vectors.cpp`).
- **`aeslib.gcm`** — GHASH known-answer tests, AES-128-GCM/AES-256-GCM
  known-answer tests cross-checked against two independent implementations
  (Python's `cryptography` and `pycryptodome`), round-trip/
  tamper-detection/wrong-key tests, GCM container format edge cases, and
  nonce/tag freshness checks (see `tests/test_gcm.cpp` and DESIGN.md's
  [Additional AES modes](DESIGN.md#additional-aes-modes-aes-128--aes-gcm)).

Disable with `-DAESLIB_BUILD_TESTS=OFF` if you only want the library and
harness.

For a sanitizer build (brief 2.9 — "we will look at this with sanitizers"):

```sh
cmake -B build-san -DCMAKE_BUILD_TYPE=Debug -DAESLIB_ENABLE_SANITIZERS=ON
cmake --build build-san -j
ctest --test-dir build-san --output-on-failure
```

## Foreign-language interface

`include/aeslib/capi.h` / `src/capi.cpp` expose a C-compatible ABI — opaque
handles, `aeslib_status` return codes instead of exceptions, and explicit
buffer ownership — built as a shared library (`aeslib_c`) so it can be
loaded from another language's runtime. It's built by default
(`-DAESLIB_BUILD_C_API=OFF` to disable) and lands at `build/libaeslib_c.so`
(Linux), `build/libaeslib_c.dylib` (macOS), or
`build\Release\aeslib_c.dll`/`build\aeslib_c.dll` (Windows, depending on
generator).

`bindings/python/` is the required "at least a minimal example of calling
it from one other language": `aeslib_ffi.py` is a `ctypes` wrapper around
the C ABI, and `demo.py` uses it to run an AES-256-CTR and an
AES-256-GCM-with-AAD round trip, plus a tampered-tag rejection check —
exactly the same shape as `main.cpp`'s harness, but calling exclusively
through the C ABI rather than linking the C++ library. Run it directly:

```sh
# adjust path per platform (build/libaeslib_c.so on Linux, etc.)
AESLIB_C_LIBRARY_PATH=build/libaeslib_c.dylib python3 bindings/python/demo.py
```

It's also wired into the test suite as `aeslib.capi_python`, including
under `-DAESLIB_ENABLE_SANITIZERS=ON` on both Linux and macOS (the build
preloads ASan's own runtime ahead of the Python interpreter that runs the
test — `LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS against the
framework's unshimmed interpreter binary, see DESIGN.md for why that
matters), so `ctest` already covers it:

```sh
ctest --test-dir build --output-on-failure -R capi_python
```

See DESIGN.md's "Foreign-language interface" section for the ABI design
rationale (why opaque handles and status codes, buffer-ownership rules,
symbol visibility, and what's deliberately out of scope).

## Continuous integration

`.github/workflows/ci.yml` runs on every push/PR: native build+test on
Linux (GCC) and Windows (MSVC), an ASan+UBSan build, and — the interesting
part — the *same compiled x86_64 binary* run twice under `qemu-x86_64` with
two different emulated CPU models, one advertising AES-NI and one without
(`qemu-aes-on`/`qemu-aes-off`). A cross-compiled aarch64 build is run under
`qemu-aarch64 -cpu max` to exercise the ARM Crypto Extensions backend under
emulation (there's no matching "no crypto" leg for aarch64 — see DESIGN.md
for why). Two more jobs (`macos-arm64` on real Apple Silicon,
`linux-arm64-native` on a GitHub-hosted Arm Linux runner) build and test
natively on genuine ARM64 hardware, complementing the emulated legs. That
directly exercises brief 2.2's requirement that a single binary pick the
correct path on two different machines, rather than relying on it having
only ever been built and run on one. See DESIGN.md's "How the dispatch is
verified" section for how this was validated and its limitations.

## Scope

Beyond the challenge's core requirements, this submission implements eight
Section 3 bonus objectives. Each entry below is what was built, its test
coverage, and where to read the design rationale — kept in DESIGN.md, linked
per item rather than repeated here.

- **3.1 Unit tests.** CTest suite under `tests/` (see "Unit tests" above).
- **3.2 Additional architectures.** `src/aes_core_arm.cpp` — a second
  hardware backend using AArch64 Crypto Extensions intrinsics
  (`vaeseq_u8`/`vaesmcq_u8`), detected at runtime via
  `getauxval`/`sysctlbyname`/`IsProcessorFeaturePresent` depending on OS.
  `aes_core_hw.cpp` picks between it and AES-NI, so `Aes256Ctr`/`AesGcm`
  needed no changes. Tests: `aeslib.aes_core` (existing KATs now run against
  whichever backend the build targets) plus the `qemu-aarch64`/
  `macos-arm64`/`linux-arm64-native` CI jobs. Design:
  [ARM AArch64 Crypto Extensions](DESIGN.md#additional-architectures-arm-aarch64-and-risc-v-after-that).
- **3.4 Safer key storage.** `SecretKey::save_to_file_encrypted`/
  `load_from_file_encrypted` — PBKDF2-HMAC-SHA256 (600,000 iterations) +
  AES-256-CTR + HMAC-SHA256, encrypt-then-MAC, a versioned wire format
  supporting both key sizes. Tests: `aeslib.key_storage`. Design:
  [Safer key storage](DESIGN.md#safer-key-storage).
- **3.5 Key generation ergonomics.** `SecretKey` has no public raw-byte
  accessor; `generate()`/`load_from_file()` are `[[nodiscard]]` named
  factories. Covered incidentally by `aeslib.key`. Design:
  [Key generation ergonomics](DESIGN.md#key-generation-ergonomics).
- **3.6 Minimizing key exposure in memory.** `mlock`/`VirtualLock` +
  `MADV_DONTDUMP`, volatile-write wipe on destruction, raw-syscall file I/O,
  wiped round-key schedules. Tests:
  `key.generate_increases_locked_memory_on_linux` plus wipe checks in
  `aeslib.key`. Design:
  [Minimizing key exposure in memory](DESIGN.md#minimizing-key-exposure-in-memory).
- **Additional AES modes.** AES-128 key support plus `AesGcm` (NIST SP
  800-38D), sharing a templated software backend and a separate AES-NI
  key-expansion routine; its own `src/ghash.cpp`. CBC was deliberately
  skipped — both backends are forward-cipher-only, and CBC is a weaker
  security property than GCM. Tests: `aeslib.gcm` plus AES-128 KATs in
  `aeslib.aes_core`. Design:
  [Additional AES modes](DESIGN.md#additional-aes-modes-aes-128--aes-gcm).
- **Generic types via templates.** `encrypt`/`decrypt_as<T>` overloads on
  `Aes256Ctr`/`AesGcm` for any byte-viewable `T`, via C++17 SFINAE traits in
  `include/aeslib/byte_view.hpp`. Tests: `aeslib.generic`. Design:
  [Generic support for other types via templates](DESIGN.md#generic-support-for-other-types-via-templates).
- **3.7 Foreign-language interface.** `include/aeslib/capi.h`/`src/capi.cpp`
  — opaque handles, status codes, explicit buffer ownership, built as
  `aeslib_c`; `bindings/python/` is the ctypes example (see below). Tests:
  `aeslib.capi_python`. Design:
  [Foreign-language interface](DESIGN.md#foreign-language-interface).

## AI tool usage disclosure

Claude (Anthropic), via Claude Code, was used as a pair-programmer across
this submission, covering implementation, tests, CI, and documentation. All
code was reviewed and is understood by the author.
