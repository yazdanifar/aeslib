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

Seven suites are registered (`aeslib.aes_core`, `aeslib.ctr`,
`aeslib.container`, `aeslib.key`, `aeslib.key_storage`, `aeslib.backend`,
`aeslib.reference_vectors`), covering: four independent AES-256 known-answer
tests (FIPS-197 Appendix C.3, NIST SP 800-38A F.1.5, and two NIST CAVP
all-zero/all-ones edge cases) against both backends, an exhaustive check of
the software backend's constant-time S-box against the canonical 256-entry
table (see DESIGN.md's "Constant-time software S-box"), CTR round-trips at a
range of sizes (including partial-final-block cases), correct counter
increment across multiple blocks, a boundary test for the 32-bit
block-counter guard, CTR's expected bit-flip malleability, nonce freshness,
container/key file format edge cases (bad magic, unsupported version,
truncated/mismatched-length data), known-answer tests for the from-scratch
SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231), and PBKDF2-HMAC-SHA256
(RFC 7914) primitives plus passphrase-protected key file round-trip,
wrong-passphrase, and tamper-detection tests (see DESIGN.md's "Safer key
storage (bonus 3.4)"), a CI hook for asserting which dispatch path is
active (see `tests/test_backend.cpp` and the CI workflow below), and seven
AES-256-CTR ciphertexts cross-checked against an independent implementation
(Python's `cryptography` library, itself cross-verified against the
`openssl` CLI — see `tests/test_reference_vectors.cpp`). Disable with
`-DAESLIB_BUILD_TESTS=OFF` if you only want the library and harness.

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

This submission implements the challenge's core requirements plus four
Section 3 bonus objectives: the unit-test suite (3.1), safer key storage (3.4),
key generation ergonomics (3.5), and minimizing key exposure in memory (3.6).

**Bonus 3.4 — Safer key storage**: `SecretKey::save_to_file_encrypted(path,
passphrase, iterations)` and `load_from_file_encrypted(path, passphrase)`
implement PBKDF2-HMAC-SHA256 key derivation (per RFC 8018, OWASP-recommended
600,000 iterations) with AES-256-CTR encryption and HMAC-SHA256 authentication
(encrypt-then-MAC, constant-time tag verification). The wrapped-key file format
is a fixed 101-byte structure: magic "AESW", version, 128-bit random salt,
iteration count, fresh nonce, wrapped ciphertext, and HMAC tag. Design verified
against NIST SP 800-132, age encryption specification, and OpenSSH's bcrypt_pbkdf.

**Bonus 3.5 — Key generation ergonomics**: `SecretKey` has no public raw-byte
accessor, so an external caller has no way to accidentally copy, log, or serialize
key bytes; the only sanctioned way to get key material out is the explicit
`save_to_file()` or `save_to_file_encrypted()`.

**Bonus 3.6 — Minimizing key exposure in memory**: `SecretKey` locks its backing
pages against swap (`mlock`/`VirtualLock`, plus `madvise(MADV_DONTDUMP)` on Linux
to exclude from core dumps); file I/O uses raw syscalls to avoid iostream
streambuf copies; both AES backends wipe derived round-key schedules after each
block. See DESIGN.md for threat model (protects against offline key theft,
tampering detection via HMAC, precomputation via random salt; does *not*
protect against weak passphrases, keyloggers, or live attacker on machine).

Test coverage: Seven suites now include `aeslib.key_storage` (known-answer
tests for SHA-256/HMAC-SHA256/PBKDF2-HMAC-SHA256 against FIPS 180-4/RFC
4231/RFC 7914 reference vectors, round-trip encryption/decryption,
wrong-passphrase rejection, file-tampering detection, format validation,
salt/nonce randomness).

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
- **Key-exposure hardening (bonus 3.6)** — a follow-up pass adding
  `mlock`/`VirtualLock` swap protection to `SecretKey`, and wiping the derived
  round-key schedule in both AES backends after each block. A research pass —
  reading how libsodium, OpenSSL, and Bitcoin Core handle the same problem,
  plus Microsoft's documentation of `VirtualLock`'s weaker guarantee versus
  POSIX `mlock`, and the cold-boot-attack literature — surfaced two gaps:
  `mlock` alone doesn't exclude pages from Linux core dumps, and
  `std::ofstream`/`std::ifstream` create unwiped streambuf copies. Both were
  fixed: `madvise(MADV_DONTDUMP)` on Linux and raw syscalls for key I/O.
- **Safer key storage (bonus 3.4)** — a comprehensive feature, with upfront
  research against OWASP, NIST SP 800-132, RFC 8018, RFC 2104, FIPS 180-4,
  FIPS 198-1, age specification, and OpenSSH bcrypt_pbkdf documentation.
  Implemented from-scratch: SHA-256 per FIPS 180-4, HMAC-SHA256 per RFC 2104,
  PBKDF2 per RFC 8018 (OWASP-recommended 600,000 iterations, while noting
  OWASP itself ranks PBKDF2 below Argon2id/scrypt/bcrypt — chosen here for
  implementation simplicity given this project's no-external-dependencies
  constraint, a disclosed tradeoff), constant-time byte comparison, and
  secure memory wiper. Encrypted key file uses 101-byte fixed format with
  magic "AESW", random 128-bit salt, PBKDF2-derived AES and HMAC subkeys,
  AES-256-CTR-wrapped key, and HMAC-SHA256 tag (verify-before-decrypt).
  A follow-up independent review pass fetched the RFC 4231/FIPS 180-4/RFC
  7914 reference vectors directly and cross-checked the implementation
  against them (rather than relying on the round-trip tests alone, which
  can't catch an internally self-consistent but wrong primitive since save
  and load call the same function), catching and fixing two things this
  process surfaced: a silent-truncation footgun in `hmac_sha256`'s
  internal buffer sizing for oversized inputs, and its use of a stack
  buffer sized for arbitrary-length data even in PBKDF2's inner loop where
  the data is always exactly 32 bytes — both replaced with buffers sized to
  the actual input. Test coverage: known-answer tests for all three
  primitives against the RFC/FIPS vectors, round-trip encryption/decryption,
  wrong-passphrase rejection, file-tampering detection, format validation,
  salt/nonce randomness.
- **Documentation** — this README and DESIGN.md (with updated Scope and feature descriptions).

All code was reviewed and is understood by the author. Both AES-256 backends
are validated against the official FIPS-197 Appendix C.3 known-answer test
on every CI run, and the documented limitations of the QEMU-based dispatch
verification (see DESIGN.md) reflect deliberate scoping decisions rather
than unexamined output.
