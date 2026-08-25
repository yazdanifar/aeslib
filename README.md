# aeslib

A small C++17 library implementing AES-256-CTR and AES-GCM (AES-128 or
AES-256) encryption/decryption with runtime dispatch between a hardware path
(AES-NI on amd64, ARM AArch64 Crypto Extensions on arm64, RV64 Zkne on
riscv64) and a portable software fallback, plus a minimal versioned
container format for storing encrypted data separately from its key.

See [DESIGN.md](DESIGN.md) for the architecture, the hardware/software
dispatch mechanism, the on-disk container formats, and the nonce strategy.

## TL;DR

- **What**: AES-256-CTR (core) + AES-128/256-GCM (bonus), C++17, `std::byte`
  throughout, runtime hardware/software dispatch (AES-NI / ARM Crypto
  Extensions / RISC-V Zkne), verified on real hardware and under QEMU with
  the CPU's AES feature bit forced on/off.
- Dispatch doesn't stop at reading the CPUID/HWCAP/hwprobe bit — it also
  runs a known-answer encryption through the hardware backend and only
  reports "Hardware" if the result matches, since a hypervisor/emulator/
  erratum can misreport a capability bit. See DESIGN.md's ["Functional
  self-verification of the hardware path"](DESIGN.md#functional-self-verification-of-the-hardware-path).
- **Storage**: key and ciphertext always land in separate, versioned files;
  an optional passphrase-wrapped key format (PBKDF2 + AES-CTR + HMAC,
  encrypt-then-MAC) is also available.
- **Memory**: `SecretKey` is move-only, has no raw-byte accessor, is
  `mlock`ed against swap, and is wiped with a compiler-proof (`volatile`)
  write on destruction.
- **Scope**: all ten §3 bonus items are attempted — see DESIGN.md's
  ["Assumptions & ambiguities"](DESIGN.md#assumptions--ambiguities) for that
  tradeoff and what would be cut first under a tighter deadline.

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
  amd64, ARM Crypto Extensions on arm64, RV64 Zkne on riscv64) or software
  AES path is in use on the current machine.
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
library and OS APIs (`BCryptGenRandom` on Windows, `getrandom(2)` on Linux,
`arc4random_buf` on other POSIX platforms such as macOS/BSD), so there is
nothing else to install.

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

Eleven tests are registered with CTest. Ten are C++ suites under `tests/`
(one file per suite unless noted), listed below; the eleventh,
`aeslib.capi_python`, runs the Python binding against the C ABI and is
described under ["Foreign-language interface"](#foreign-language-interface).
See each suite's linked DESIGN.md section for what it's actually checking
and why:

| Suite | Covers | Design reasoning |
| --- | --- | --- |
| `aeslib.aes_core` | AES-256/AES-128 known-answer tests against both backends; exhaustive constant-time-S-box check | [Constant-time software S-box](DESIGN.md#constant-time-software-s-box) |
| `aeslib.ctr` | Round-trips, partial-final-block, counter increment, overflow boundary, bit-flip malleability, nonce freshness | [Nonce/IV strategy](DESIGN.md#2-nonceiv-strategy) |
| `aeslib.container`, `aeslib.key` | On-disk format edge cases (bad magic, bad version, truncated data) | [On-disk container format](DESIGN.md#3-on-disk-container-format) |
| `aeslib.key_storage` | SHA-256/HMAC/PBKDF2 KATs; passphrase-key round-trip, tamper, and iteration-count validation | [Safer key storage](DESIGN.md#safer-key-storage) |
| `aeslib.backend` | Dispatch-path assertion for CI; the `AESLIB_FORCE_SOFTWARE` override; hardware self-verification's rejection path | [Functional self-verification of the hardware path](DESIGN.md#functional-self-verification-of-the-hardware-path) |
| `aeslib.reference_vectors` | Seven AES-256-CTR ciphertexts cross-checked against an independent implementation | [Nonce/IV strategy](DESIGN.md#2-nonceiv-strategy) |
| `aeslib.gcm` | GHASH/GCM KATs, round-trip, tamper-detection, container edge cases | [Additional AES modes](DESIGN.md#additional-aes-modes-aes-128--aes-gcm) |
| `aeslib.generic` | Templated `encrypt`/`decrypt_as<T>` round-trips over several byte-viewable types | [Generic support via templates](DESIGN.md#generic-support-for-other-types-via-templates) |
| `aeslib.capi` | C ABI argument validation, round-trips, tamper detection (only when `AESLIB_BUILD_C_API` is on, the default) | [Foreign-language interface](DESIGN.md#foreign-language-interface) |

Disable with `-DAESLIB_BUILD_TESTS=OFF` if you only want the library and
harness.

For a sanitizer build (brief 2.7 — "we will look at this with sanitizers"):

```sh
cmake -B build-san -DCMAKE_BUILD_TYPE=Debug -DAESLIB_ENABLE_SANITIZERS=ON
cmake --build build-san -j
ctest --test-dir build-san --output-on-failure
```

### ISA-isolation check

`scripts/verify_isa_isolation.sh` disassembles the built object files and
confirms AES-NI / AArch64 Crypto Extensions / RV64 Zkne instructions only
ever appear in the one translation unit each is scoped to in
`CMakeLists.txt` — the property that makes runtime hardware dispatch safe
across machines in the first place (see
[DESIGN.md](DESIGN.md#1-cryptography-core)). Needs `objdump` or
`llvm-objdump` on `PATH`; run it after building:

```sh
scripts/verify_isa_isolation.sh build
```

## Fuzzing

`fuzz/` has three [libFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses
for the parsers that take fully attacker-controlled bytes: the CTR and GCM
container formats and the passphrase-protected key file loader. Supplementary
coverage on top of the malformed-input unit tests above — not part of the
default `ctest` run.

Requires Clang (`-fsanitize=fuzzer` isn't available on GCC or MSVC):

```sh
cmake -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DAESLIB_BUILD_FUZZERS=ON -DAESLIB_BUILD_TESTS=OFF
cmake --build build-fuzz -j
./build-fuzz/fuzz_container -max_total_time=60
./build-fuzz/fuzz_gcm_container -max_total_time=60
./build-fuzz/fuzz_key_file -max_total_time=60
```

Each harness builds `aeslib` with ASan+UBSan so a memory-safety or UB bug
surfaces as a sanitizer report. **macOS note:** Homebrew's LLVM Clang
(`brew install llvm`) is required on Apple Silicon — the Xcode Command Line
Tools' bundled Clang doesn't ship the `-fsanitize=fuzzer` runtime.

## Foreign-language interface

`include/aeslib/capi.h` / `src/capi.cpp` expose a C-compatible ABI (opaque
handles, status codes instead of exceptions) built as a shared library,
`aeslib_c` (`-DAESLIB_BUILD_C_API=OFF` to disable). It lands at
`build/libaeslib_c.so` (Linux), `build/libaeslib_c.dylib` (macOS), or
`build\Release\aeslib_c.dll` (Windows).

`bindings/python/` is the minimal example of calling it from another
language: `aeslib_ffi.py` is a `ctypes` wrapper, `demo.py` round-trips
AES-256-CTR and AES-256-GCM-with-AAD and checks tampered-tag rejection.

```sh
AESLIB_C_LIBRARY_PATH=build/libaeslib_c.dylib python3 bindings/python/demo.py
```

It's also registered as the `aeslib.capi_python` CTest test, so `ctest`
already covers it:

```sh
ctest --test-dir build --output-on-failure -R capi_python
```

See DESIGN.md's "Foreign-language interface" section for the ABI design
rationale.

## Using this library as a dependency

Pull it into another CMake project with `FetchContent`, then link the
`aeslib` target (add `aeslib_c` too if you also want the C ABI):

```cmake
include(FetchContent)
FetchContent_Declare(aeslib GIT_REPOSITORY <this-repo-url> GIT_TAG main)
set(AESLIB_BUILD_TESTS OFF) # skip aeslib's own test suite in a consumer build
FetchContent_MakeAvailable(aeslib)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE aeslib)
```

(A checked-out copy also works with `add_subdirectory(path/to/aeslib)`
instead of `FetchContent`.)

```cpp
#include "aeslib/aes256_ctr.hpp"
#include "aeslib/key.hpp"

aeslib::SecretKey key = aeslib::SecretKey::generate();
aeslib::Container container = aeslib::Aes256Ctr::encrypt(key, plaintext);
aeslib::save_container(container, "data.enc");
key.save_to_file("data.key");
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push/PR:

<!-- markdownlint-disable MD013 -->
| Job | What it runs |
| --- | --- |
| `linux-x86_64` | Native build + test (GCC), real AES-NI hardware |
| `windows-msvc` | Native build + test (MSVC) |
| `linux-sanitizers` | ASan+UBSan build + test |
| `qemu-aes-on` / `qemu-aes-off` | The *same* compiled x86_64 binary, run under two emulated CPU models — one advertising AES-NI, one without |
| `qemu-aarch64` | Cross-compiled aarch64 build, run under emulation |
| `macos-arm64` / `linux-arm64-native` | Native build + test on real ARM64 hardware |
| `qemu-riscv64` | Cross-compiled riscv64 build, run under emulation |
<!-- markdownlint-enable MD013 -->

The `qemu-aes-on`/`qemu-aes-off` pair proves the same compiled binary is
correct on both a capable and an incapable machine, rather than assuming it.
See DESIGN.md's ["Verifying dispatch is real, not
assumed"](DESIGN.md#verifying-dispatch-is-real-not-assumed) for details.

## Scope

Beyond the core requirements, this submission attempts all ten §3 bonus
objectives — see DESIGN.md's ["Assumptions &
ambiguities"](DESIGN.md#assumptions--ambiguities) for that tradeoff. Each
item's design rationale lives in DESIGN.md's "Bonus objectives", linked per
row; this table is just the checklist and test suite to look at.

<!-- markdownlint-disable MD013 -->
| Brief item | What | Design | Tests |
| --- | --- | --- | --- |
| 3.1 Unit tests | CTest suite under `tests/` | (this file, "Unit tests" above) | — |
| 3.2 Additional architectures | ARM AArch64 + RISC-V (RV64 Zkne) hardware backends | [Additional architectures](DESIGN.md#additional-architectures-arm-aarch64-and-risc-v) | `aeslib.aes_core`, `qemu-aarch64`, `qemu-riscv64`, `macos-arm64`, `linux-arm64-native` |
| 3.3 Additional AES modes | AES-128 key support + AES-GCM | [Additional AES modes](DESIGN.md#additional-aes-modes-aes-128--aes-gcm) | `aeslib.gcm`, `aeslib.aes_core` |
| 3.4 Safer key storage | Passphrase-wrapped key file (PBKDF2 + AES-CTR + HMAC) | [Safer key storage](DESIGN.md#safer-key-storage) | `aeslib.key_storage` |
| 3.5 Key generation ergonomics | No raw-byte accessor reachable from the public headers; `[[nodiscard]]` named factories | [Key generation ergonomics](DESIGN.md#key-generation-ergonomics) | `aeslib.key` |
| 3.6 Minimizing key exposure in memory | `mlock`/`VirtualLock`, volatile-write wipe, raw-syscall I/O, wiped schedules | [Minimizing key exposure in memory](DESIGN.md#minimizing-key-exposure-in-memory) | `aeslib.key` |
| 3.7 Generic types via templates | `encrypt`/`decrypt_as<T>` for any byte-viewable `T` | [Generic support via templates](DESIGN.md#generic-support-for-other-types-via-templates) | `aeslib.generic` |
| 3.8 Foreign-language interface | C ABI (`capi.h`) + Python `ctypes` binding | [Foreign-language interface](DESIGN.md#foreign-language-interface) | `aeslib.capi`, `aeslib.capi_python` |
| 3.9 Anything else | Sanitizer builds, constant-time S-box, forced-path CI matrix | [Constant-time software S-box](DESIGN.md#constant-time-software-s-box) | see "Continuous integration" above |
| 3.10 Using CMake | CMake is the sole build system | — | — |
<!-- markdownlint-enable MD013 -->

## AI tool usage disclosure

**Tools used.** Claude (Anthropic) through Claude Code, as a pair programmer across the whole
submission — implementation, tests, CMake and CI, and prose. Standards text (FIPS-197,
SP 800-38A, SP 800-38D, FIPS 180-4, RFC 4231, RFC 7914) was fetched and read directly rather
than recalled by the model: every vector in `tests/test_reference_vectors.cpp` and
`src/kat_vector.hpp` is transcribed from a published source, not from model output.

**How I worked.** I decided the architecture and every security-relevant policy, then used the
model to write code against those decisions and to argue with me about them. Nothing was
accepted because it compiled and round-tripped — a round trip can't distinguish a correct
primitive from an internally self-consistent wrong one, since save and load call the same code.
That is why the from-scratch SHA-256, HMAC-SHA256, and PBKDF2 primitives are pinned to
published known-answer vectors.

### Where it was used, and what I owned

<!-- markdownlint-disable MD013 -->

| Area | Model's role | Mine |
| --- | --- | --- |
| Dispatch seam (`aes_core_hw.cpp`, `cpu_detect.cpp`, `aes_core_{ni,arm,riscv}.cpp`) | Intrinsics and the per-architecture CPUID/HWCAP reads | The seam itself (one mode driver → arch-neutral `_hw()` wrapper → per-arch backend), and the self-verification step: a known-answer test runs before the library reports "hardware", so a lying hypervisor or an emulator gap degrades to software instead of producing garbage |
| Software fallback (`aes_core_soft.cpp`) | Portable S-box and round code | Reviewed for data-dependent branching and table indexing — this is the path that must not leak timing |
| Key material (`key.cpp`, `key_storage.cpp`) | RAII wrapper, PBKDF2/HMAC, `mlock`/`VirtualLock` plumbing | Move-only handle with volatile wipe, encrypt-then-MAC ordering with the tag covering the header, salt, iteration count and nonce as well as the ciphertext, the iteration-count bounds, and the threat model in DESIGN.md — including what passphrase wrapping does *not* protect against |
| Nonce and container (`csprng.cpp`, `container.cpp`) | Serialization code | Nonce strategy (a fresh 96-bit CSPRNG nonce per `encrypt()` call, `nonce‖counter` as the CTR input block), the birthday-bound reasoning and its limits, the versioned container header, and the rejection rules for truncated or mismatched files |
| Build system and CI | CMake scaffold, workflow YAML, first draft of `scripts/verify_isa_isolation.sh` | Per-file ISA flags, the matrix that runs the *same binary* with hardware AES forced on and off, and the disassembly check that proves no AES-NI / Crypto-Extensions / Zkne opcode leaks out of the single translation unit CMake scopes it to |
| Tests and fuzzing | Harness boilerplate | Which cases matter: counter overflow, partial blocks, nonce freshness, bad magic, truncation, forced-backend equivalence, GCM invocation limits |
| C ABI and Python binding | `ctypes` scaffolding and glue | Error taxonomy and handle lifetime rules |
| README and DESIGN.md | Structure, examples, editing | All reasoning, trade-offs, and security claims |

<!-- markdownlint-enable MD013 -->

### Three things the model got wrong that I caught

These are the honest evidence that the output was read rather than shipped:

1. **`hmac_sha256` sized a fixed 64 KB stack buffer on every call** and silently truncated
   oversized input. In PBKDF2's inner loop that path runs about 1.2M times at the default
   600,000 iterations, always with exactly 32 bytes of input. Found during a verification pass
   against RFC 4231; replaced with buffers sized to the actual input, and the missing
   primitive-level KATs were added (`a930449`).
2. **`SecretKey`'s move constructor and move assignment never carried `size_`**, so a moved
   AES-128 key reported itself as AES-256 over storage whose top 16 bytes are zero — wrong
   ciphertext rather than a visible failure. Reachable from the shipped C ABI, since
   `aeslib_key_generate(128, ...)` move-constructs the opaque handle. Fixed with three
   regression tests; the pre-existing move test missed it because it only ever exercised a
   256-bit key (`a21cd1a`).
3. **DESIGN.md asserted that no `getenv` call exists under `src/`**, while `cpu_detect.cpp`
   reads `AESLIB_FORCE_SOFTWARE` inside `active_backend()` in the shipped library.
   Plausible-sounding documentation that contradicted the code; corrected, and the real
   behaviour and its risk are now stated (`2db9a92`).

### What I can answer for

I can walk any part of this end to end: plaintext → `Aes256Ctr::encrypt()` → CTR keystream
blocks → `aes256_encrypt_block_hw()` → the backend selected at runtime → container
serialization, and back. Ask me why the software S-box is written the way it is, why
`SecretKey` is move-only with no raw-byte accessor, why the MAC covers the header and not just
the ciphertext, or why the CI matrix is shaped the way it is — including the parts I would do
differently with more time.
