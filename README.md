# aeslib

A small C++17 library implementing AES-256-CTR and AES-GCM (AES-128 or
AES-256) encryption/decryption with runtime dispatch between an AES-NI
hardware path and a portable software fallback, plus a minimal versioned
container format for storing encrypted data separately from its key.

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
- `aeslib::save_container` / `load_container` (CTR) and
  `aeslib::save_gcm_container` / `load_gcm_container` (GCM), plus
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

Eight suites are registered (`aeslib.aes_core`, `aeslib.ctr`,
`aeslib.container`, `aeslib.key`, `aeslib.key_storage`, `aeslib.backend`,
`aeslib.reference_vectors`, `aeslib.gcm`), covering: independent AES-256 and
AES-128 known-answer tests (FIPS-197 Appendix C.3/C.1, NIST SP 800-38A
F.1.5, and two NIST CAVP all-zero/all-ones edge cases) against both
backends, an exhaustive check of the software backend's constant-time S-box
against the canonical 256-entry table (see DESIGN.md's "Constant-time
software S-box"), CTR round-trips at a range of sizes (including
partial-final-block cases), correct counter increment across multiple
blocks, a boundary test for the 32-bit block-counter guard, CTR's expected
bit-flip malleability, nonce freshness, container/key file format edge
cases (bad magic, unsupported version, truncated/mismatched-length data),
known-answer tests for the from-scratch SHA-256 (FIPS 180-4), HMAC-SHA256
(RFC 4231), and PBKDF2-HMAC-SHA256 (RFC 7914) primitives plus
passphrase-protected key file round-trip, wrong-passphrase, tamper-detection,
and iteration-count-validation tests (see DESIGN.md's "Safer key storage
(bonus 3.4)"), a CI hook for asserting which dispatch path is active (see
`tests/test_backend.cpp` and the CI workflow below), seven AES-256-CTR
ciphertexts cross-checked against an independent implementation (Python's
`cryptography` library, itself cross-verified against the `openssl` CLI —
see `tests/test_reference_vectors.cpp`), and — the new AES-128/AES-GCM bonus —
GHASH known-answer tests, AES-128-GCM and AES-256-GCM known-answer tests
cross-checked against two independent implementations (Python's
`cryptography` and `pycryptodome`), round-trip/tamper-detection/wrong-key
tests, GCM container format edge cases, and nonce/tag freshness checks (see
`tests/test_gcm.cpp` and DESIGN.md's "Additional AES modes"). Disable with
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

This submission implements the challenge's core requirements plus five
Section 3 bonus objectives: the unit-test suite (3.1), safer key storage (3.4),
key generation ergonomics (3.5), minimizing key exposure in memory (3.6), and
additional AES modes (AES-128 + AES-GCM).

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

Test coverage: `aeslib.key_storage` (known-answer tests for
SHA-256/HMAC-SHA256/PBKDF2-HMAC-SHA256 against FIPS 180-4/RFC 4231/RFC 7914
reference vectors, round-trip encryption/decryption, wrong-passphrase
rejection, file-tampering detection, format validation, salt/nonce
randomness).

**Bonus — Additional AES modes**: `aeslib::SecretKey::generate(KeySize::Aes128)`
adds 128-bit key support alongside the existing 256-bit default, and
`aeslib::AesGcm::encrypt(key, plaintext, aad)` /
`AesGcm::decrypt(key, container, aad)` implement AES-GCM (NIST SP 800-38D),
an authenticated mode, for either key size. The software AES backend
(`src/aes_core_soft.cpp`) was refactored from an AES-256-only implementation
into a `template <int Nk, int Nr>` shared by both key sizes; the AES-NI
backend gets a separate, independently-implemented AES-128 key-expansion
routine (`expand_key128_ni`, following Intel's published AES-NI key-schedule
pattern) alongside the existing AES-256 one, since the two schedules'
structures differ enough that sharing code wasn't a good fit. GHASH
(`src/ghash.cpp`) is implemented from spec (GF(2^128) multiplication,
branch-free/constant-time in both operands) and has its own known-answer
tests independent of the full AES-GCM round trip. CBC mode was deliberately
not implemented — GCM only needs the forward AES cipher, which both
backends already have; CBC decryption would require implementing the AES
inverse cipher (`InvSubBytes` etc.) in both backends for a weaker security
property (no authentication) than GCM already provides. `Aes256Ctr` and
`SecretKey::save_to_file_encrypted`/`load_from_file_encrypted` (bonus 3.4)
remain AES-256-only; the latter now explicitly throws `LimitError` for an
AES-128 key rather than silently mishandling one. See DESIGN.md's
"Additional AES modes" section for the full design rationale, including why
GCM nonce reuse is a strictly worse failure mode than CTR's.

Test coverage: `aeslib.gcm` (GHASH known-answer tests; AES-128-GCM and
AES-256-GCM known-answer tests cross-checked against two independent
implementations — Python's `cryptography` library and `pycryptodome`;
round-trip encryption/decryption with and without AAD; tampered-ciphertext,
tampered-tag, tampered-AAD, and wrong-key rejection; GCM container format
edge cases; nonce/tag freshness), plus new AES-128 known-answer tests
(FIPS-197 Appendix C.1) in `aeslib.aes_core` and key-size/format tests in
`aeslib.key`.

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
  A **third** review pass, focused specifically on `src/key_storage.cpp` and
  its surrounding files, found and fixed two more issues: (1) the
  PBKDF2-derived AES/HMAC subkeys and decrypted-key scratch buffers were
  wiped via a manual `secure_wipe()` call placed before each `return`, which
  several `throw` statements (on internal sanity-check failures, or a
  propagated `Aes256Ctr::decrypt` failure) could skip — replaced with a
  `detail::ScopedWipe` RAII guard that wipes on scope exit regardless of how
  the function exits, alongside the existing manual calls for the
  "wipe-as-soon-as-possible" property in the normal path; (2)
  `load_from_file_encrypted` ran PBKDF2 using an iteration count read
  directly from the file's own untrusted header, before the HMAC tag could
  be checked (checking the tag requires the PBKDF2-derived MAC subkey) — a
  corrupted or hostile file claiming a huge iteration count could force an
  effectively unbounded computation ahead of any authentication check, and
  `iterations == 0` was separately accepted on both save and load despite
  silently collapsing PBKDF2 to one HMAC evaluation. Both are now validated
  (`LimitError`/`FormatError`) before PBKDF2 runs.
  A **fourth** pass cross-checked this fix against prior art via web search
  and found the `age` encryption tool's own postmortem on the identical bug
  shape in its scrypt recipient (github.com/FiloSottile/age/issues/417):
  rejecting only `iterations == 0` isn't sufficient, since a hostile or
  corrupted file could instead claim a small-but-nonzero count and get away
  with negligible PBKDF2 stretching — the same "file header controls its own
  KDF work factor" problem, just at the opposite (low) end from the DoS case
  above. Both `save_to_file_encrypted` and `load_from_file_encrypted` now
  enforce NIST SP 800-132's PBKDF2 floor (`kMinPbkdf2Iterations` = 1000)
  instead of only a nonzero check. See DESIGN.md's "Safer key storage
  (bonus 3.4)" for detail.
- **Additional AES modes (AES-128 + AES-GCM)** — upfront web research
  against NIST SP 800-38D (the GCM specification), Intel's "Advanced
  Encryption Standard Instructions (AES-NI)" white paper (Gueron, for the
  AES-128 key-schedule pattern), and the GCM nonce-reuse literature (Joux's
  "forbidden attack" and the 2016 "Nonce-Disrespecting Adversaries" survey)
  before implementing, informing the scope decision to implement GCM
  instead of CBC (documented in DESIGN.md) and the explicit nonce-reuse
  caveat added to the design doc's "Nonce/IV strategy" section. Implemented
  from scratch: the software AES backend's `expand_key`/block-encrypt
  functions were refactored into a `template <int Nk, int Nr>` shared by
  AES-128 and AES-256 (verified behaviorally identical for AES-256 by the
  pre-existing FIPS-197 C.3 KAT continuing to pass unchanged); the AES-NI
  backend's AES-128 key expansion was written as a new, independent
  function rather than adapted from the existing AES-256 one, since the two
  schedules' structures differ; and GHASH (GF(2^128) multiplication and the
  GHASH recursion) was implemented directly against NIST SP 800-38D,
  written branch-free for the same constant-time reasons as the existing
  S-box. GCM known-answer test vectors were generated with Python's
  `cryptography` library and then independently cross-checked against a
  second, unrelated library (`pycryptodome`) before being hardcoded as
  expected values — the GHASH-specific KATs were additionally verified
  against a from-scratch Python re-implementation of GF(2^128)
  multiplication, independent of both. See DESIGN.md's "Additional AES
  modes" section for the full design rationale and scope limitations.
- **Documentation** — this README and DESIGN.md (with updated Scope and feature descriptions).

All code was reviewed and is understood by the author. Both backends are
validated against the official FIPS-197 Appendix C.3 (AES-256) and Appendix
C.1 (AES-128) known-answer tests on every CI run, and the documented
limitations of the QEMU-based dispatch verification (see DESIGN.md) reflect
deliberate scoping decisions rather than unexamined output.
