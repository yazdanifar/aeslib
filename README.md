# aeslib

A small C++17 library implementing AES-256-CTR encryption/decryption with
runtime dispatch between an AES-NI hardware path and a portable software
fallback, plus a minimal versioned container format for storing encrypted
data separately from its key.

See [DESIGN.md](DESIGN.md) for the architecture, the hardware/software
dispatch mechanism, the on-disk container format, and the nonce strategy.

## What it does

- `aeslib::SecretKey::generate()` — generates a 256-bit key via the OS
  CSPRNG.
- `aeslib::Aes256Ctr::encrypt(key, plaintext)` /
  `aeslib::Aes256Ctr::decrypt(key, container)` — operate on
  `std::vector<std::byte>`.
- `aeslib::save_container` / `load_container` and
  `SecretKey::save_to_file` / `load_from_file` — persist ciphertext and key
  to **separate** files.
- `aeslib::active_backend()` — reports whether the hardware (AES-NI) or
  software AES path is in use on the current machine.

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

Not included in this submission — the optional unit-test bonus objective
from the challenge brief wasn't attempted. The software AES-256 core was
validated during development against the FIPS-197 Appendix C.3 known-answer
test vector, and the `main.cpp` harness exercises the full
encrypt → store → load → decrypt round trip described above.

## Scope

This submission implements the challenge's core requirements only (no
Section 3 bonus objectives): AES-256-CTR, runtime AES-NI/software dispatch
on amd64, `std::vector<std::byte>` APIs with file load/store, a documented
versioned container format with key/ciphertext stored separately, a CMake
build, and the `main.cpp` harness described above.

## AI tool usage disclosure

This library, its documentation, and the accompanying design notes were
written with the assistance of Claude (Anthropic), used as a pair-programmer
for implementation, cross-checking the AES-256 key schedule/round
transforms against FIPS-197, and drafting documentation. All code was
reviewed and is understood by the author; the software AES-256
implementation was independently validated against the official FIPS-197
Appendix C.3 test vector as part of that review.
