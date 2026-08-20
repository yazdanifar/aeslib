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
AESLIB_C_LIBRARY_PATH=build/libaeslib_c.dylib python3 bindings/python/demo.py   # adjust path per platform
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

This submission implements the challenge's core requirements plus eight
Section 3 bonus objectives: the unit-test suite (3.1), additional
architectures (3.2 — ARM AArch64 Crypto Extensions), safer key storage (3.4),
key generation ergonomics (3.5), minimizing key exposure in memory (3.6),
additional AES modes (AES-128 + AES-GCM), generic support for other types via
templates, and a foreign-language interface (3.7).

**Bonus 3.2 — Additional architectures**: `src/aes_core_arm.cpp` adds a
second hardware backend, AES-256/AES-128 forward-cipher encryption using
AArch64 Crypto Extensions intrinsics (`vaeseq_u8`/`vaesmcq_u8`), detected at
runtime the same way AES-NI is (never compile-time-baked-in) via
`getauxval(AT_HWCAP)` on Linux, `sysctlbyname("hw.optional.arm.FEAT_AES")` on
macOS, or `IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)`
on Windows ARM64. `Aes256Ctr`/`AesGcm` needed no code changes to support it:
a new `src/aes_core_hw.cpp` centralizes the choice between the AES-NI and
ARM backends behind arch-neutral `aesNNN_encrypt_block_hw()` wrappers, so the
mode logic that used to call the AES-NI functions by name now calls those
instead. Unlike AES-NI, ARM's Crypto Extensions have no dedicated
key-expansion instruction, so the round-key schedule is shared with the
software backend (`src/aes_key_schedule.hpp`) rather than reimplemented a
third time. See DESIGN.md's "ARM AArch64 Crypto Extensions" section for the
round-loop derivation and why RISC-V would be the next straightforward
architecture given this abstraction.

Test coverage: the existing hardware-path KATs and soft/hardware
cross-checks in `aeslib.aes_core` now run against whichever backend the
build targets (via `_hw`, not the AES-NI functions directly), so they
validate ARM for free on ARM hardware; a new
`expand_key_matches_fips197_appendix_a3` test checks the shared schedule
directly against FIPS-197's published AES-256 key expansion; CI runs the
cross-compiled aarch64 binary under `qemu-aarch64 -cpu max`, plus two native
ARM64 jobs (`macos-arm64` on Apple Silicon, `linux-arm64-native` on a
GitHub-hosted Arm Linux runner) confirming the real hardware path on two
different real chips. Unlike x86-64, there's no QEMU-aarch64 "no crypto"
leg — every QEMU-modeled aarch64 CPU reports the extension present, since
real ARMv8-A silicon has shipped with it almost universally since the
Cortex-A53/A57 generation, so QEMU doesn't offer a realistic "modern core
without it" model the way it does for AES-NI's Nehalem; see DESIGN.md.

**Bonus 3.4 — Safer key storage**: `SecretKey::save_to_file_encrypted(path,
passphrase, iterations)` and `load_from_file_encrypted(path, passphrase)`
implement PBKDF2-HMAC-SHA256 key derivation (per RFC 8018, OWASP-recommended
600,000 iterations) with AES-256-CTR encryption and HMAC-SHA256 authentication
(encrypt-then-MAC, constant-time tag verification). The wrapped-key file format
is a version-2, `70 + key_size`-byte structure: magic "AESW", version, key-size
marker (16 or 32, matching the wrapped key's own size), 128-bit random salt,
iteration count, fresh nonce, wrapped ciphertext, and HMAC tag — the wrapping
key derived from the passphrase is always AES-256, but only the caller's own
key's logical bytes are ever wrapped, so this works for both AES-128 and
AES-256 keys. Design verified against NIST SP 800-132, age encryption
specification, and OpenSSH's bcrypt_pbkdf.

**Bonus 3.5 — Key generation ergonomics**: `SecretKey` has no public raw-byte
accessor, so an external caller has no way to accidentally copy, log, or serialize
key bytes; the only sanctioned way to get key material out is the explicit
`save_to_file()` or `save_to_file_encrypted()`.

**Bonus 3.6 — Minimizing key exposure in memory**: `SecretKey` locks its backing
pages against swap (`mlock`/`VirtualLock`, plus `madvise(MADV_DONTDUMP)` on Linux
to exclude from core dumps); file I/O uses raw syscalls to avoid iostream
streambuf copies; all AES backends wipe derived round-key schedules after each
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
property (no authentication) than GCM already provides. `Aes256Ctr` also
dispatches on key size the same way `AesGcm` does, and
`SecretKey::save_to_file_encrypted`/`load_from_file_encrypted` (bonus 3.4)
now support both key sizes too (see that section above). See DESIGN.md's
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

**Bonus — Generic support for other types via templates**:
`Aes256Ctr`/`AesGcm` gained template overloads of `encrypt` and a new
`decrypt_as<T>`, alongside (not replacing) the existing
`std::vector<std::byte>` baseline. `include/aeslib/byte_view.hpp` defines
the constraint a type `T` needs to satisfy: either a contiguous container of
trivially copyable elements (`std::vector<X>`, `std::array<X,N>`,
`std::string`, ...), viewed element-wise, or a single trivially copyable
object (e.g. a plain struct), viewed as one `sizeof(T)`-byte blob — expressed
as C++17 SFINAE traits over `std::is_trivially_copyable`, since this project
targets C++17 and has neither `std::span` nor concepts available.
`decrypt_as<T>` throws `FormatError` if the decrypted byte count doesn't fit
`T` (wrong `sizeof(T)` for an object, or not a whole multiple of the element
size for a resizable container; a fixed-size `std::array<X,N>` must match
`N * sizeof(X)` exactly since it can't be resized to fit). See DESIGN.md's
"Generic support for other types via templates" section for the full
constraint reasoning, including why `is_trivially_copyable` is necessary but
not sufficient for "safe to persist."

Test coverage: `aeslib.generic` — round-trip encryption/decryption through
both `Aes256Ctr` and `AesGcm` for `std::vector<uint8_t>`, `std::array<std::byte,N>`,
`std::array<uint8_t,N>`, `std::string`, `std::vector<int32_t>`, and a plain
POD struct; `FormatError` on a byte-count mismatch for a fixed-size array, a
non-multiple-of-element-size vector, and a wrong-size struct; a sanity check
that the template `encrypt` path produces ciphertext identical to what the
untouched `std::vector<std::byte>` baseline path produces for the same
bytes; plus compile-time `static_assert`s proving the trait rejects
non-trivially-copyable types (a struct holding a `std::vector` member, a
`std::vector<std::string>`).

**Bonus 3.7 — Foreign-language interface**: `include/aeslib/capi.h` /
`src/capi.cpp` add a C-compatible ABI covering key generation/load/save,
AES-256-CTR, and AES-GCM, built as a new `aeslib_c` shared-library CMake
target. Design choices: an opaque `aeslib_key_t` handle (the header never
depends on `SecretKey`'s C++ layout); `aeslib_status` return codes mapped
1:1 from the existing exception hierarchy plus a thread-local
`aeslib_last_error_message()`, since a C++ exception unwinding across an
`extern "C"` boundary into another language's runtime is undefined
behavior; fixed-size caller-allocated arrays for the nonce/tag (already
compile-time-constant sizes) but library-allocated heap buffers + a
matching `aeslib_buffer_free()` for variable-length ciphertext/plaintext,
to avoid the classic cross-allocator free() mismatch at a shared-library
boundary (especially relevant on Windows, where a DLL and its caller can
have distinct CRT heaps); and hidden-by-default symbol visibility with an
explicit `AESLIB_C_API` export macro, so only the intended `aeslib_*`
symbols are part of the exported surface. `bindings/python/` is the
required example from a second language: `aeslib_ffi.py`, a `ctypes`
wrapper declaring explicit `argtypes`/`restype` for every exported
function, and `demo.py`, which round-trips AES-256-CTR and
AES-256-GCM-with-AAD through the C ABI and confirms a tampered GCM tag is
rejected with `AESLIB_ERR_AUTHENTICATION` rather than silently accepted.
See DESIGN.md's "Foreign-language interface" section for the full design
rationale, cited sources, and stated scope limits (passphrase-wrapped key
storage isn't exposed through the C ABI; the Python smoke test also runs
under the sanitizer build, on both Linux and macOS, by preloading ASan's
runtime ahead of the interpreter that runs it — macOS additionally needed
routing around a framework-`python3` shim/`posix_spawn` quirk, see
DESIGN.md).

Test coverage: `aeslib.capi_python` (registered via CTest, see
`CMakeLists.txt`) runs `bindings/python/demo.py` against the just-built
`aeslib_c` library on every `ctest` invocation — an actual cross-language
round trip, not just a compile check — covering AES-256-CTR and
AES-256-GCM-with-AAD round trips plus GCM tamper-detection through the C
ABI specifically (as opposed to the pre-existing `aeslib.gcm`/`aeslib.ctr`
suites, which exercise the C++ API directly).

## AI tool usage disclosure

Claude (Anthropic), via Claude Code, was used as a pair-programmer across this submission, covering implementation, tests, CI, and documentation. All code was reviewed and is understood by the author.
