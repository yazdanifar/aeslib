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

A CTest-based suite lives under `tests/`, using a small hand-rolled
assertion header (`tests/test_support.hpp`) rather than a third-party
framework — this keeps the whole project, tests included, free of external
dependencies. Build with tests enabled (the default) and run:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Six suites are registered (`aeslib.aes_core`, `aeslib.ctr`,
`aeslib.container`, `aeslib.key`, `aeslib.backend`,
`aeslib.reference_vectors`), covering: four independent AES-256 known-answer
tests (FIPS-197 Appendix C.3, NIST SP 800-38A F.1.5, and two NIST CAVP
all-zero/all-ones edge cases) against both backends, an exhaustive check of
the software backend's constant-time S-box against the canonical 256-entry
table (see DESIGN.md's "Constant-time software S-box"), CTR round-trips at a
range of sizes (including partial-final-block cases), correct counter
increment across multiple blocks, a boundary test for the 32-bit
block-counter guard, CTR's expected bit-flip malleability, nonce freshness,
container/key file format edge cases (bad magic, unsupported version,
truncated/mismatched-length data), a CI hook for asserting which dispatch
path is active (see `tests/test_backend.cpp` and the CI workflow below), and
seven AES-256-CTR ciphertexts cross-checked against an independent
implementation (Python's `cryptography` library, itself cross-verified
against the `openssl` CLI — see `tests/test_reference_vectors.cpp`). Disable
with `-DAESLIB_BUILD_TESTS=OFF` if you only want the library and harness.

For a sanitizer build (brief 2.9 — "we will look at this with sanitizers"):

```sh
cmake -B build-san -DCMAKE_BUILD_TYPE=Debug -DAESLIB_ENABLE_SANITIZERS=ON
cmake --build build-san -j
ctest --test-dir build-san --output-on-failure
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push/PR: native build+test on
Linux (GCC) and Windows (MSVC), an ASan+UBSan build, a cross-compiled
aarch64 build run under `qemu-aarch64`, and — the interesting one — the
*same compiled x86_64 binary* run twice under `qemu-x86_64` with two
different emulated CPU models, one advertising AES-NI and one without. That
directly exercises brief 2.2's requirement that a single binary pick the
correct path on two different machines, rather than relying on it having
only ever been built and run on one. See DESIGN.md's "How the dispatch is
verified" section for how this was validated and its limitations.

## Scope

This submission implements the challenge's core requirements plus three
Section 3 bonus objectives: the unit-test suite (3.1) described above, key
generation ergonomics (3.5) — `SecretKey` has no public raw-byte accessor,
so an external caller has no way to accidentally copy, log, or serialize
key bytes; the only sanctioned way to get key material out is the explicit
`save_to_file()` — and minimizing key exposure in memory (3.6) — `SecretKey`
locks its backing pages against swap (`mlock`/`VirtualLock`, plus
`madvise(MADV_DONTDUMP)` on Linux to also exclude them from core dumps) for
as long as it's alive on top of its existing wipe-on-destruction/move
behavior; its file I/O goes through raw `read`/`write`/`ReadFile`/`WriteFile`
rather than iostreams, to avoid an unwiped copy of key bytes sitting in a
streambuf; and both AES backends now also wipe their derived round-key
schedule after each block, not just the raw key. See DESIGN.md's "Key
generation ergonomics" and "Minimizing key exposure in memory" sections for
the full writeup, sources consulted, and stated threat model (including
what this does *not* protect against, e.g. cold-boot attacks and a live
attached debugger). No other Section 3 bonus objectives were attempted.

## AI tool usage disclosure

Claude (Anthropic), via Claude Code, was used as a pair-programmer across
this submission. Specifically:

- **Library implementation** (`include/`, `src/`, `main.cpp`) — writing the
  AES-256 key schedule and round transforms for both backends, the CTR
  driver, the container format, and the CSPRNG/key-handling code, with the
  key schedule cross-checked against FIPS-197 during review.
- **Test suite** (`tests/`) — the hand-rolled assertion harness and all six
  suites, including selecting the FIPS-197 Appendix C.3 vector as the
  known-answer test and the `AESLIB_EXPECTED_BACKEND` mechanism used by CI
  to assert which dispatch path a run took.
- **CI workflow** (`.github/workflows/ci.yml`) — the job matrix, including
  the QEMU `-cpu` approach for exercising both dispatch outcomes from a
  single compiled binary. The premise that `qemu-x86_64 -cpu <model>`
  controls the guest's `CPUID` output was empirically verified on GitHub's
  runners before the workflow was written, rather than assumed.
- **Hardening pass** — a follow-up review pass that added the
  constant-time software S-box, the CTR block-counter overflow guard, the
  exhaustive S-box test, and `tests/test_reference_vectors.cpp`. The
  reference-vector ciphertexts in that file were computed locally with
  Python's `cryptography` library and independently cross-checked against
  the `openssl enc -aes-256-ctr` CLI before being hardcoded as expected
  values, rather than generated and trusted from a single source.
- **Key generation ergonomics (bonus 3.5)** — removed `SecretKey`'s public
  `bytes()` accessor in favor of an internal-only `detail::key_bytes()`
  friend function reachable only from the AES backends and tests, plus
  `[[nodiscard]]` on the key factories and marking the class `final`. This
  followed a round of checking the approach against external references
  (the SEI CERT C++ Coding Standard's rule against exposing references to
  restricted members, the misuse-resistant-API paper behind NaCl's design,
  and Rust's `secrecy` crate) before implementing, rather than guessing.
- **Key-exposure hardening (bonus 3.6)** — a further follow-up pass adding
  `mlock`/`VirtualLock` swap protection to `SecretKey`, and wiping the
  derived round-key schedule (not just the raw key) in both AES backends
  after each block. Verified by running the test harness under `ulimit -l
  0` to confirm the memlock-failure path doesn't break key generation, and
  by a clean ASan/UBSan run to catch any issue in the new byte-level
  `volatile` writes over `__m128i` storage. A later research pass — reading
  how libsodium, OpenSSL, and Bitcoin Core handle the same problem, plus
  Microsoft's own documentation of `VirtualLock`'s weaker guarantee versus
  POSIX `mlock`, and the cold-boot-attack literature — surfaced a real gap
  (`mlock` alone doesn't exclude pages from Linux core dumps) and a real,
  fixable copy (`std::ofstream`/`std::ifstream`'s internal streambuf when
  saving/loading key files). Both were fixed: `madvise(MADV_DONTDUMP)` was
  added alongside `mlock` on Linux, and `save_to_file()`/`load_from_file()`
  now use raw `read`/`write`/`ReadFile`/`WriteFile` instead of iostreams.
  DESIGN.md's threat-model paragraph was also expanded to state, rather than
  omit, the cold-boot/DRAM-remanence attack and the Windows-specific
  `VirtualLock` caveat.
- **Documentation** — this README and DESIGN.md.

All code was reviewed and is understood by the author. Both AES-256 backends
are validated against the official FIPS-197 Appendix C.3 known-answer test
on every CI run, and the documented limitations of the QEMU-based dispatch
verification (see DESIGN.md) reflect deliberate scoping decisions rather
than unexamined output.
