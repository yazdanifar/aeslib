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
  Extensions / RISC-V Zkne), verified on real hardware *and* under QEMU with
  the CPU's AES feature bit forced on/off — same binary, both outcomes.
- **The one thing worth reading first if you only read one thing**: dispatch
  doesn't stop at reading the CPUID/HWCAP/hwprobe bit. Before trusting it,
  `cpu_detect.cpp` runs a real known-answer encryption through the hardware
  backend and only reports "Hardware" if the answer matches — because a
  hypervisor, emulator, or silicon erratum can misreport a capability bit for
  an instruction it doesn't actually execute correctly. See DESIGN.md's
  ["Functional self-verification of the hardware
  path"](DESIGN.md#functional-self-verification-of-the-hardware-path).
- **Storage**: key and ciphertext always land in separate, versioned files;
  an optional passphrase-wrapped key format (PBKDF2 + AES-CTR + HMAC,
  encrypt-then-MAC) is also available.
- **Memory**: `SecretKey` is move-only, has no raw-byte accessor, is
  `mlock`ed against swap, and is wiped with a compiler-proof (`volatile`)
  write on destruction.
- **Scope**: all ten Section 3 bonus items are attempted — cheap here
  specifically because the hardware/software dispatch abstraction (§1) made
  each new backend or mode an incremental addition rather than a rewrite.
  See DESIGN.md's ["Assumptions &
  ambiguities"](DESIGN.md#assumptions--ambiguities) for what that scope call
  traded off, and what would be cut first under a tighter deadline.
- **Where to go next**: the sections below cover build/test/run instructions;
  DESIGN.md has the reasoning behind every decision above.

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

Ten suites are registered (source under `tests/`, one file per suite unless
noted); see each one's linked DESIGN.md section for what it's actually
checking and why:

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
on-disk container formats (`aeslib::deserialize`/`aeslib::deserialize_gcm`),
and the passphrase-protected key file loader
(`SecretKey::load_from_file_encrypted`). This is supplementary,
developer-facing coverage on top of the hand-picked malformed-input unit
tests in `aeslib.container`/`aeslib.gcm` above — not part of the default
`ctest` run, and not required to build or test the library normally.

Requires Clang (`-fsanitize=fuzzer` isn't available on GCC or MSVC):

```sh
cmake -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DAESLIB_BUILD_FUZZERS=ON -DAESLIB_BUILD_TESTS=OFF
cmake --build build-fuzz -j
./build-fuzz/fuzz_container -max_total_time=60
./build-fuzz/fuzz_gcm_container -max_total_time=60
./build-fuzz/fuzz_key_file -max_total_time=60
```

Each harness builds `aeslib` itself with ASan+UBSan (same as
`AESLIB_ENABLE_SANITIZERS` above) so a memory-safety or UB bug surfaces as a
sanitizer report, not just a crash. **macOS note:** on Apple Silicon,
Homebrew's LLVM Clang (`brew install llvm`) is what actually ships the
`libclang_rt.fuzzer_osx.a` runtime `-fsanitize=fuzzer` needs — the Xcode
Command Line Tools' bundled Clang doesn't include it and fails to link.

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

The `qemu-aes-on`/`qemu-aes-off` pair is what makes brief 2.2's "same
binary, correct on both a capable and an incapable machine" requirement
literal rather than assumed. See DESIGN.md's ["Verifying dispatch is real,
not assumed"](DESIGN.md#verifying-dispatch-is-real-not-assumed) for how each
job was validated and what it does and doesn't prove.

## Scope

Beyond the challenge's core requirements (brief §2), this submission
attempts all ten brief §3 bonus objectives — see DESIGN.md's ["Assumptions &
ambiguities"](DESIGN.md#assumptions--ambiguities) for the judgment call
behind attempting all ten rather than a focused subset. What each one is and
why it's built the way it is lives in DESIGN.md's "Bonus objectives"
section, linked per row below; this table is only the checklist and the test
suite to look at.

<!-- markdownlint-disable MD013 -->
| Brief item | What | Design | Tests |
| --- | --- | --- | --- |
| 3.1 Unit tests | CTest suite under `tests/` | (this file, "Unit tests" above) | — |
| 3.2 Additional architectures | ARM AArch64 + RISC-V (RV64 Zkne) hardware backends | [Additional architectures](DESIGN.md#additional-architectures-arm-aarch64-and-risc-v) | `aeslib.aes_core`, `qemu-aarch64`, `qemu-riscv64`, `macos-arm64`, `linux-arm64-native` |
| 3.3 Additional AES modes | AES-128 key support + AES-GCM | [Additional AES modes](DESIGN.md#additional-aes-modes-aes-128--aes-gcm) | `aeslib.gcm`, `aeslib.aes_core` |
| 3.4 Safer key storage | Passphrase-wrapped key file (PBKDF2 + AES-CTR + HMAC) | [Safer key storage](DESIGN.md#safer-key-storage) | `aeslib.key_storage` |
| 3.5 Key generation ergonomics | No raw-byte accessor; `[[nodiscard]]` named factories | [Key generation ergonomics](DESIGN.md#key-generation-ergonomics) | `aeslib.key` |
| 3.6 Minimizing key exposure in memory | `mlock`/`VirtualLock`, volatile-write wipe, raw-syscall I/O, wiped schedules | [Minimizing key exposure in memory](DESIGN.md#minimizing-key-exposure-in-memory) | `aeslib.key` |
| 3.7 Generic types via templates | `encrypt`/`decrypt_as<T>` for any byte-viewable `T` | [Generic support via templates](DESIGN.md#generic-support-for-other-types-via-templates) | `aeslib.generic` |
| 3.8 Foreign-language interface | C ABI (`capi.h`) + Python `ctypes` binding | [Foreign-language interface](DESIGN.md#foreign-language-interface) | `aeslib.capi`, `aeslib.capi_python` |
| 3.9 Anything else | Sanitizer builds, constant-time S-box, forced-path CI matrix | [Constant-time software S-box](DESIGN.md#constant-time-software-s-box) | see "Continuous integration" above |
| 3.10 Using CMake | CMake is the sole build system | — | — |
<!-- markdownlint-enable MD013 -->

## AI tool usage disclosure

Claude (Anthropic), via Claude Code, was used as a pair-programmer across
this submission, covering implementation, tests, CI, and documentation. All
code was reviewed and is understood by the author.
