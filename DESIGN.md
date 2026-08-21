# Design

Architecture and reasoning behind the key decisions in this library.

## Layout

```text
include/aeslib/       public API headers
  aes256_ctr.hpp       Aes256Ctr — the encrypt/decrypt entry point
  aes_gcm.hpp          AesGcm — authenticated mode (bonus)
  key.hpp              SecretKey — RAII key holder
  backend.hpp          Backend enum + active_backend() query
  container.hpp        on-disk ciphertext container + file I/O helpers
  byte_view.hpp        byte-viewable-type traits for the generic
                        encrypt/decrypt_as<T> overloads (bonus)
  exceptions.hpp       IoError / FormatError / LimitError / AuthenticationError
  capi.h                C-compatible ABI (bonus, see "Foreign-language
                        interface") — the one header not written in C++
src/                   implementation
  aes256_ctr.cpp        CTR-mode driver: builds counter blocks, dispatches
                        to a backend, XORs the keystream
  aes_gcm.cpp            GCM driver: keystream generation + GHASH tag (bonus)
  aes_core_soft.cpp      portable AES forward cipher (FIPS-197), no
                        intrinsics, used as the fallback
  aes_core_ni.cpp        AES forward cipher using AES-NI intrinsics (amd64)
  aes_core_arm.cpp       AES forward cipher using AArch64 Crypto Extensions
                        intrinsics (bonus)
  aes_core_hw.cpp        the one file that knows there's more than one
                        hardware backend — arch-neutral aesNNN_..._hw()
                        wrappers CTR/GCM call instead of _ni/_arm directly
  aes_key_schedule.hpp   shared FIPS-197 key-expansion template, used by
                        both aes_core_soft.cpp and aes_core_arm.cpp
  ghash.cpp              GF(2^128) multiplication + GHASH for GCM (bonus)
  cpu_detect.cpp          runtime hardware-AES capability check (CPUID on
                        amd64; HWCAP/sysctl/IsProcessorFeaturePresent on
                        arm64, depending on OS)
  csprng.cpp              OS CSPRNG wrapper
  key.cpp                key (de)serialization and file I/O
  key_storage.cpp         passphrase-wrapped key storage (bonus)
  container.cpp           ciphertext container (de)serialization and file I/O
  internal.hpp             shared declarations, not part of the public API
  capi.cpp                 implements capi.h: opaque-handle wrapping,
                        exception-to-status-code translation (bonus)
main.cpp                end-to-end harness (see README.md)
bindings/python/       ctypes binding + demo for capi.h (bonus)
```

## 1. Cryptography core

### AES-256-CTR and the hardware/software split

`Aes256Ctr` builds CTR-mode counter blocks and XORs the resulting keystream
against the input; the actual AES block encryption is delegated to whichever
backend is active. Because CTR mode only ever needs the forward AES
transform, every backend implements encryption only — there is no AES
decryption routine anywhere in this codebase.

### Runtime dispatch

`aeslib::active_backend()` runs a hardware-capability check the first time
it's called and memoizes the result in a function-local static, so the
decision is made once, at runtime, on whatever machine the binary happens to
be running on. It is never baked in via `#ifdef __AES__` or
`-march=native`: the same compiled binary takes the hardware path on a
capable host and the software path on one without, which is what lets one
binary be correct on both.

What the capability check actually reads depends on the target
architecture — `CPUID.1:ECX.AESNI` (bit 25) on amd64, or one of three
OS-specific reads of the AArch64 Crypto Extensions feature bit on arm64 (see
"Additional architectures" below) — but the caller-facing shape is identical
either way: `cpu::has_hw_aes()` returns one bool, and `active_backend()`
turns that into `Backend::Hardware` / `Backend::Software`. `Aes256Ctr` /
`AesGcm` call `active_backend()` internally to pick which block-encrypt
function to use; callers of the public API never see this decision, but it's
exposed as a free function so tests and diagnostics can observe it (the
`main.cpp` harness prints which path ran).

Each hardware backend's intrinsics live in their own translation unit
(`aes_core_ni.cpp` for AES-NI, `aes_core_arm.cpp` for AArch64 Crypto
Extensions) and are the *only* files compiled with an architecture-specific
flag (`-maes` / `-march=armv8-a+crypto` on GCC/Clang; see `CMakeLists.txt`).
Every other file — including the CTR/GCM drivers that call into them —
stays free of any architecture-specific instruction-set flags. That's what
makes it safe to ship as one portable binary: the compiler never emits a
hardware-AES instruction outside those two files, and each is only ever
called after `cpu::has_hw_aes()` has confirmed the corresponding
instructions are safe to execute.

`aes_core_hw.cpp` is the single seam that knows there are now two possible
hardware backends, never more than one real in a given build: it exposes
arch-neutral `aesNNN_encrypt_block_hw()` wrappers implemented purely as
`#if`/`#elif` on the target architecture (x86 → `_ni`, arm64 → `_arm`,
anything else → throws). `aes256_ctr.cpp` / `aes_gcm.cpp` call only `_hw`,
never `_ni`/`_arm` by name, which is what let ARM support (below) be added
with a one-line change to each mode driver rather than a rewrite.

### Verifying dispatch is real, not assumed

The requirement is that the *same binary* be correct on a machine with
hardware AES acceleration and one without. `.github/workflows/ci.yml`
verifies this on every push, rather than resting on a one-off manual check:

- **`linux-x86_64`** builds and tests natively on real AES-NI hardware
  (confirmed `Hardware` in the harness output) and uploads the compiled test
  binaries as an artifact.
- **`qemu-aes-on`** / **`qemu-aes-off`** download that *exact same
  artifact* and run it under `qemu-x86_64-static -cpu Westmere` (AES-NI
  present) and `-cpu Nehalem` (AES-NI absent) respectively.
  `tests/test_backend.cpp` asserts `active_backend()` matches what each CPU
  model should produce, via an `AESLIB_EXPECTED_BACKEND` env var read only
  by that test file — one binary, one build, two CPU identities, two
  different correct outcomes.
- **`qemu-aarch64`** cross-compiles for arm64 and runs under
  `qemu-aarch64-static -cpu max`, exercising `aes_core_arm.cpp`'s real
  implementation under emulation. There is no matching "-off" leg: every
  QEMU-modeled aarch64 CPU reports the Crypto Extensions as present, since
  they've been near-universal on real ARMv8-A silicon since Cortex-A53/A57 —
  QEMU's models reflect that rather than offering a "modern core without it"
  option the way Nehalem does for x86-64. The software path on arm64 is
  still proven correct without a dedicated leg, since it's the same portable
  code already exercised by the amd64 software-path legs.
- **`macos-arm64`** and **`linux-arm64-native`** build and test natively on
  two genuine ARM64 machines (no cross toolchain, no emulation), both
  expected to report `Hardware` unconditionally. These complement the QEMU
  jobs: QEMU proves dispatch under a controlled, togglable CPU model; these
  two prove the same code behaves correctly on real silicon, which QEMU's
  TCG can't fully stand in for.

Before writing the amd64 jobs, the premise that `qemu-x86_64 -cpu <model>`
actually controls what a guest binary's `CPUID` reports (rather than passing
through the host's real capabilities) was verified directly against GitHub's
runners: `-cpu Westmere`, `Nehalem`, `max`, and `max,-aes` produced AES-NI
`yes`/`yes`/`yes`/`no` respectively, as expected.

**A limitation worth stating plainly:** QEMU's TCG will generally still
*execute* an `aesenc` instruction even when the CPUID feature bit is masked
off — real silicon would `SIGILL`. So `qemu-aes-off` proves detection
correctly reports hardware AES as absent and that the software fallback is
byte-correct; it does not prove dispatch would fail safely if the hardware
branch were ever taken on real hardware genuinely lacking the extension.
That gap is closed by the dispatch logic itself being simple enough to read
completely (a handful of `#if` branches in `cpu_detect.cpp`, each reading
one OS-provided capability flag), not by execution — which is also why the
two native-hardware jobs matter: they run the real detection code against
real silicon, not an emulator's approximation of it.

A standalone known-answer test (FIPS-197 Appendix C.3, AES-256) is also run
directly against `aes256_encrypt_block_hw()` and `aes256_encrypt_block_soft()`
in `tests/test_aes_core.cpp`, confirming both produce the exact published
ciphertext block for the same key/plaintext on every CI run, including the
ARM legs.

### Constant-time software S-box

A textbook software AES implementation substitutes bytes via
`kSBox[secret_byte]` — a lookup table indexed by secret data, and a
classical cache-timing side channel (which cache line the lookup touches
depends on the secret byte, and that's observable by another process on the
same core). Neither hardware backend has this problem (`aesenc` and
`AESE`/`AESMC` are constant-time by construction), but a naive software
fallback would have it silently.

`src/aes_core_soft.cpp`'s `ct_sbox()` replaces the table with a computed
substitution: GF(2^8) multiplicative inversion via a fixed
square-and-multiply chain to the 254th power (`x^-1 == x^254` for `x != 0`,
matching the S-box's own `0 -> 0` convention), followed by the standard
FIPS-197 §5.1.1 affine bit transform. The exponent is a compile-time
constant, so the sequence of squarings/multiplications is identical for
every input — no branch depends on the secret byte's value, only
branch-free bit-masking (`gmul`'s `mask = -(b & 1)` pattern) touches it. Both
`sub_bytes()` (the block round transform) and `sub_word()` (the Nk=8 key
schedule) route through this same function, so neither touches a
secret-indexed table anywhere in the software path.
`tests/test_aes_core.cpp`'s `ct_sbox_matches_canonical_table_exhaustively`
compares `ct_sbox(b)` against the textbook 256-entry S-box for every
possible byte value, in addition to the FIPS-197 KAT.

### Why not a general crypto library for the software path

Pulling in OpenSSL/libsodium/mbedTLS purely to get software AES would trade
a well-specified, well-tested ~80 lines of textbook Rijndael for a much
larger, harder-to-audit dependency and a more fragile cross-platform build
(`FetchContent`/`find_package` version pinning, ABI shims for MSVC, etc.).
AES-256 is completely specified by FIPS-197 and validated here against the
official Appendix C.3 known-answer test, so writing it directly keeps the
library dependency-free and easy to audit end to end. This is a
scope-specific call, not a recommendation to hand-roll crypto in a real
production system with a real threat model — there, a vetted,
actively-maintained library is almost always the right choice, specifically
because of the ongoing side-channel and implementation-bug hardening a
bespoke implementation doesn't get for free.

## 2. Nonce/IV strategy

Each `Aes256Ctr::encrypt()` call generates a fresh 96-bit nonce from the OS
CSPRNG and combines it with a 32-bit big-endian block counter (starting at
0) to form the 128-bit CTR input block — the same nonce||counter
construction AES-GCM uses. The nonce is stored alongside the ciphertext in
the container (below); the counter is never stored, since it's implicit in
a block's position in the stream.

Correctness therefore only depends on the pair (key, nonce) never
repeating. Because the nonce is random per encryption rather than tracked
as a counter across the key's lifetime, the birthday bound applies: for a
given key, the probability of a nonce collision becomes non-negligible only
after roughly 2^48 encryptions under that key — far beyond what a single
key in this library is expected to encrypt. A production system doing
extremely high-volume encryption under one long-lived key would want a
stateful (counter-based, not random) nonce instead; that tradeoff didn't
seem worth the added complexity (persisting nonce-counter state across
process restarts) for this library's scope.

The 32-bit counter caps a single message at 2^32 blocks (64 GiB) before it
would wrap and start reusing keystream within that one message. This is
enforced, not just documented: `Aes256Ctr::encrypt()`/`decrypt()` call
`detail::validate_block_count()` first and throw `LimitError` rather than
silently wrapping if a caller ever hands them more data than that.

**Why the test suite doesn't use published NIST CTR vectors.** NIST SP
800-38A's CTR vectors (F.5.5/F.5.6) use a free-running 128-bit counter block
with no separate nonce field, whereas this library splits that same 128
bits into a 96-bit random nonce and a 32-bit counter, so the published
vectors don't apply directly to this format. Correctness is anchored at
three levels instead: the block-cipher layer (`tests/test_aes_core.cpp`,
checked against FIPS-197 Appendix C.3, NIST SP 800-38A F.1.5, and two NIST
CAVP all-zero/all-ones edge cases, plus the exhaustive S-box check above);
CTR-level tests (`tests/test_ctr.cpp`) covering round-trips, nonce
freshness, wrong-key decryption, correct counter increment, the
counter-overflow guard at its exact boundary, and CTR's expected bit-flip
malleability; and `tests/test_reference_vectors.cpp`, which hardcodes seven
AES-256-CTR ciphertexts for this exact nonce||counter construction
(single-block, multi-block, partial final block, all-zero/all-ones
key/nonce/data, single-byte input), computed independently via Python's
`cryptography` library and cross-checked against the `openssl enc
-aes-256-ctr` CLI. That file documents how each vector was generated so it
can be reproduced or extended.

**Why nonce reuse is strictly worse under GCM than under CTR.** `AesGcm`
(see "Additional AES modes" below) uses this same nonce||counter
construction for its keystream, plus a GHASH-based authentication tag.
Under plain CTR, reusing a (key, nonce) pair leaks the XOR of the two
plaintexts — bad, but limited to confidentiality. Under GCM, it's worse in
kind, not just degree: Joux's "forbidden attack" shows that two ciphertexts
authenticated under the same (key, nonce) let an attacker solve a
low-degree polynomial equation over GF(2^128) for the GHASH subkey `H`
itself, since `H` is a fixed, key-derived constant appearing identically in
both tags' computation. Once `H` is recovered, the attacker can forge a
valid tag for *any* ciphertext of their choosing under that key — not just
replay or bit-flip an existing message, but construct new ones the receiver
will accept as authentic. The "Nonce-Disrespecting Adversaries" survey
(2016) found real HTTPS servers reusing GCM nonces in practice, most from
buggy random-nonce generation or counter state not carried correctly across
failover. `AesGcm::encrypt()` still uses a fresh random 96-bit nonce per
call (same birthday-bound reasoning as CTR) for exactly this reason: a
random nonce has the same collision probability as CTR's, but the
consequence of a collision is qualitatively worse for GCM.

**GCM's per-key usage limit is tighter than the raw birthday bound.**
[NIST SP 800-38D §8.3](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf)
states it directly: "the probability that the [GCM] authenticated
encryption function ... is invoked with the same IV ... and the same key
... more than once shall be exceeded with probability no greater than
2^-32" for randomly generated 96-bit IVs, which — by the standard birthday
calculation for a 96-bit space — caps the *recommended* number of
encryptions under one key at **2^32**, not the ~2^48 figure that's the
right answer to "when does a collision become more likely than not."
Those are two different questions: ~2^48 is where two random 96-bit values
are more likely than not to collide at least once; 2^32 is where the
*cumulative probability of any collision at all* first exceeds a
cryptographically negligible 2^-32. NIST's normative limit uses the
stricter bar deliberately, because GCM's failure mode on a nonce collision
is a full key compromise (the forbidden attack above), not merely a
confidentiality leak the way it is for plain CTR — a risk profile that
warrants a safety margin, not "solve for the point of even odds."

This library enforces that per-key limit, rather than leaving it as a
documented-only caller responsibility: each `SecretKey` carries a private,
`mutable std::atomic<std::uint64_t>` invocation counter
(`detail::consume_gcm_invocation`, `include/aeslib/key.hpp`/`src/key.cpp`),
incremented once per `AesGcm::encrypt()` call and checked against
`detail::kGcmInvocationLimit` (`src/internal.hpp`) *before* that call spends
a random nonce; the 2^32+1th encryption under the same `SecretKey` object
throws `LimitError` instead of proceeding. This is deliberately scoped to
match the "random nonce, no persisted counter" design chosen above, not a
reversal of it: the counter lives on the in-memory `SecretKey` object (and
moves with it, since move is the only way to relocate one), so it bounds
usage within one object's lifetime, not across process restarts or
independent `SecretKey` instances loaded from the same key file — closing
the *in-process* runaway-usage gap (a long-lived server calling
`AesGcm::encrypt()` on one loaded key far past 2^32 times) without taking on
the added complexity of persisting nonce-counter state across restarts,
which the earlier "why nonce reuse is strictly worse under GCM" reasoning
already judged not worth it for this library's scope. Tested at the
boundary directly via `detail::check_gcm_invocation_count(std::uint64_t)`
(`tests/test_gcm.cpp`'s `invocation_limit_*` tests) rather than by actually
performing 2^32 encryptions, the same reason the CTR/GCM block-counter guard
is tested via `detail::validate_block_count(size)` on a plain size rather
than a real ~64 GiB buffer.

`Aes256Ctr`'s birthday-bound reasoning is unaffected by any of this — CTR's
failure mode on nonce reuse is the strictly milder XOR-of-plaintexts leak,
so NIST's stricter GCM-specific limit doesn't apply to it, and `Aes256Ctr`
carries no equivalent counter.

## 3. On-disk container format

Key and ciphertext are always written to **separate files** — the
container never carries key material, so leaking one file doesn't leak
plaintext without also having the other. All formats carry an explicit
version byte so a future format change can be introduced without breaking
the ability to read files written by an older library version.

Ciphertext container (`.aesc`), all integers little-endian:

| bytes | field      | meaning                              |
|-------|------------|---------------------------------------|
| 0–3   | magic      | ASCII `"AESC"`                        |
| 4     | version    | format version, currently `1`         |
| 5–16  | nonce      | 12-byte CTR nonce                     |
| 17–24 | ct_len     | `uint64_t`, ciphertext length in bytes|
| 25–   | ciphertext | `ct_len` bytes                        |

GCM ciphertext container (`.aesg`, bonus — see "Additional AES modes"),
using a distinct magic so the two file types can't be confused:

| bytes | field      | meaning                                |
|-------|------------|-----------------------------------------|
| 0–3   | magic      | ASCII `"AESG"`                         |
| 4     | version    | format version, currently `1`          |
| 5–16  | nonce      | 12-byte GCM nonce                      |
| 17–32 | tag        | 16-byte GCM authentication tag         |
| 33–40 | ct_len     | `uint64_t`, ciphertext length in bytes |
| 41–   | ciphertext | `ct_len` bytes                         |

Key file (version 2): `version (1 byte)` + `size_marker (1 byte, = 16 or
32)` + `size_marker` raw key bytes, written with `0600` permissions on
POSIX. (Version 1, predating AES-128 support, had no size marker and
always wrote 32 bytes; bumped rather than kept compatible since no real
persisted files exist outside this repo's own tests.)

## 4. Key handling

`SecretKey` is move-only — copying is disabled at the type level, so a key
can't be accidentally duplicated by value — and every consumer in this
codebase (`aes256_ctr.cpp`, both AES backends) takes it by `const&`, so no
incidental copies of the raw key exist anywhere in the library. Its
hardened API surface, storage, and memory-lifetime behavior are covered
under the relevant bonus sections below.

## 5. Error handling

Four exception types cover this library's failure modes: `aeslib::IoError`
(filesystem/OS failures), `aeslib::FormatError` (malformed container/key
files), `aeslib::LimitError` (a request exceeds a format-imposed size
limit, or asks for an operation this library deliberately doesn't support —
the CTR/GCM block-counter bounds, or `save_to_file_encrypted` rejecting an
invalid iteration count), and `aeslib::AuthenticationError` (a
passphrase-protected key file's HMAC tag doesn't verify, or a GCM
container's tag doesn't verify — wrong passphrase/key/nonce/AAD, or a
tampered/corrupted file; kept distinct from `FormatError` so callers can
tell "ask for the passphrase again" apart from "file is unreadable").
Nothing in the public API uses output-parameter error codes.

## 6. Known limitations / threat model

- **No authentication.** CTR mode as implemented here provides
  confidentiality only, not integrity. Ciphertext is malleable: flipping a
  bit in the ciphertext flips the corresponding bit in the decrypted
  plaintext, undetected, since there is no MAC or tag anywhere in the `.aesc`
  container format. A caller needing tamper-evidence can layer one on (e.g.
  HMAC over the container), or use `AesGcm` instead, which already provides
  it. This is a scope boundary, not an oversight — the core brief specifies
  CTR, which is inherently unauthenticated.
- **Nonce birthday bound.** Random 96-bit nonces mean collision risk becomes
  non-negligible only after ~2^48 encryptions under one key — far beyond
  this library's expected single-key volume, but a real bound rather than
  "impossible" (§2). For `AesGcm` specifically, NIST SP 800-38D §8.3's own
  recommended limit is far more conservative than that: 2^32 encryptions per
  key. This one *is* enforced, per-`SecretKey`-object, via
  `detail::consume_gcm_invocation`/`check_gcm_invocation_count` (§2) —
  `AesGcm::encrypt()` throws `LimitError` past 2^32 calls on the same key
  object, though (as noted there) the counter doesn't survive a process
  restart or a fresh `SecretKey` reloaded from the same key file.
- **Software-path cache timing** is addressed, not just documented: see
  "Constant-time software S-box" (§1).

## 7. Test/production isolation

- The `AESLIB_EXPECTED_BACKEND` environment variable CI uses to assert
  which dispatch path ran (§1) is read in exactly one place in the entire
  codebase: `tests/test_backend.cpp`. No `getenv` call exists anywhere
  under `src/` or `include/` — production dispatch (`cpu::has_hw_aes()`,
  `active_backend()`) is driven purely by the hardware-capability check and
  cannot be steered by any environment variable.
- `src/internal.hpp` (the internal declarations tests need to reach
  directly — `Block`, `aes256_encrypt_block_*`, `cpu::has_hw_aes`,
  `rng::fill_random`, `ct_sbox`, `validate_block_count`) is included only by
  production `.cpp` files under `src/`, never by anything under
  `include/aeslib/`. A consumer linking `aeslib` through its public include
  directory never sees it.
- The `aeslib` CMake target lists only production sources; `aeslib_tests`
  is a separate executable, and its include path to reach `internal.hpp` is
  scoped `PRIVATE` to that test target only.
- `-DAESLIB_BUILD_TESTS=OFF` removes `add_subdirectory(tests)` from the
  build entirely; the `aeslib` library target is unaffected either way.
- There is no `install()`/`export()` rule in this project, so nothing
  currently packages test code, `internal.hpp`, or anything else for
  distribution.

---

## Bonus objectives

### Additional architectures: ARM AArch64 and RISC-V

The dispatch model deliberately isolates *all* architecture-specific code
behind one interface: functions with an identical signature
(`Block aesNNN_encrypt_block_*(const SecretKey&, const Block&)`) plus a
one-function CPU-capability check — the isolation described in §1. Adding
ARM support meant three touch points, none of which reached
`aes256_ctr.cpp`/`aes_gcm.cpp` beyond a one-line `_ni` → `_hw` rename:

- **`aes_core_hw.cpp`** gained an arm64 `#elif` branch dispatching to
  `_arm` instead of `_ni`.
- **`cpu::has_hw_aes()`** (`src/cpu_detect.cpp`) gained three OS-specific
  arm64 branches, since "does this CPU support the AArch64 Crypto
  Extensions" has no single cross-platform answer:
  - Linux: `getauxval(AT_HWCAP) & HWCAP_AES`.
  - macOS (Apple Silicon): `sysctlbyname("hw.optional.arm.FEAT_AES", ...)`.
  - Windows on ARM64: `IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)`.

  Each is read once and memoized, like the x86 CPUID check. An arm64 target
  under an unrecognized OS falls back to `false` (software path) rather
  than guessing.
- **`aes_core_arm.cpp`**, the new backend itself.

**No key-expansion instruction, unlike AES-NI.** x86's AES-NI has
`_mm_aeskeygenassist_si128`, a dedicated key-schedule-assist instruction,
which is why `aes_core_ni.cpp` has its own hand-written schedule routine.
ARM's Crypto Extensions have no equivalent — `AESE`/`AESMC` only accelerate
the 16-round block *transform*, not the schedule — so, following mbedTLS's
and Botan's own ARM backends, the round-key schedule is computed in
portable code instead: the existing `expand_key<Nk,Nr>` template was
extracted from `aes_core_soft.cpp`'s anonymous namespace into
`src/aes_key_schedule.hpp`, a shared internal header both `aes_core_soft.cpp`
and `aes_core_arm.cpp` include. `aes_core_arm.cpp` calls it, packs each
16-byte round key into a `uint8x16_t`, and runs the standard ARMv8 round
loop:

```cpp
state = vld1q_u8(block);
for (i = 0; i < Nr - 1; ++i) {
    state = vaeseq_u8(state, rk[i]);   // fused AddRoundKey+SubBytes+ShiftRows
    state = vaesmcq_u8(state);         // MixColumns
}
state = vaeseq_u8(state, rk[Nr - 1]);  // final round: no MixColumns
state = veorq_u8(state, rk[Nr]);       // final AddRoundKey
```

`vaeseq_u8(x, k)` computes `ShiftRows(SubBytes(x ^ k))` — AddRoundKey fused
into the *next* round's SubBytes/ShiftRows rather than applied at the end of
the previous one. This still reproduces textbook FIPS-197 encryption
because SubBytes and ShiftRows commute (ShiftRows only permutes byte
positions; SubBytes substitutes every byte identically regardless of
position), so folding round *r*'s trailing AddRoundKey into round *r+1*'s
leading SubBytes/ShiftRows is equivalent to the textbook order. The
round-key schedule is wiped the same volatile-write way every other backend
wipes derived key material (see "Minimizing key exposure in memory"),
both as the `Word` array and as the packed `uint8x16_t` copy.

**Build isolation.** Same rationale as `-maes` for `aes_core_ni.cpp`:
`aes_core_arm.cpp` is the only file compiled with `-march=armv8-a+crypto`
on GCC/Clang (`CMakeLists.txt`'s `AESLIB_TARGET_IS_ARM64` branch). MSVC
targeting ARM64 needs no equivalent flag — `<arm_neon.h>` exposes the
crypto intrinsics unconditionally when targeting ARM64, since Windows'
ARM64 baseline always presumes NEON even though the crypto extensions
themselves remain an optional hardware feature checked at runtime.

**Test reuse, not new test code.** `tests/test_aes_core.cpp`'s existing
hardware-path KAT and cross-check tests were changed to call
`aesNNN_encrypt_block_hw(...)` instead of `_ni` by name — the same one-line
substitution the production code got — so they now exercise whichever
hardware backend the build actually targets, with zero new arch-specific
test code. A new `expand_key_matches_fips197_appendix_a3` test checks the
now-shared schedule template directly against FIPS-197 Appendix A.3's
published 60-word AES-256 expansion, localizing a schedule bug independent
of round-transform correctness now that the schedule is shared by two
backends.

**A third architecture, built rather than just argued for: RISC-V.** This
started as brief 3.2's "extra credit if a third architecture would be
straightforward" argument in prose. It's now a real backend, added through
exactly the three touch points the ARM section above predicted, with no
changes to `aes256_ctr.cpp`, `aes_gcm.cpp`, or anything under `include/`:

- **`aes_core_hw.cpp`** gained a `#elif defined(__riscv) && __riscv_xlen ==
  64` branch dispatching to `_riscv` instead of `_ni`/`_arm`.
- **`cpu::has_hw_aes()`** (`src/cpu_detect.cpp`) gained a Linux riscv64
  branch. Unlike ARM, this doesn't go through `getauxval(AT_HWCAP)` — HWCAP
  only has bits for base ISA letters, not sub-extensions like `Zkne` — so it
  uses the `riscv_hwprobe()` syscall instead (invoked directly via
  `syscall(2)` with the kernel UAPI `<asm/hwprobe.h>` struct/macros, rather
  than glibc's `<sys/hwprobe.h>` wrapper, since that wrapper only landed in
  glibc 2.39 and the raw syscall works against any glibc version), checking
  `RISCV_HWPROBE_KEY_IMA_EXT_0` for the `Zkne` bit (only — `Zknd`, the
  decryption extension, is never checked or required; see below). A riscv64
  target under an unrecognized OS falls back to `false`, same as every other
  architecture's catch-all.
- **`aes_core_riscv.cpp`**, the new backend itself, targeting **RV64GC +
  Zkne** (scalar AES; the vector `Zvkned` extension was left for a future
  pass — Zkne alone already answers brief 3.2's question).

**Dedicated key-schedule-assist instructions, unlike ARM.** RV64's scalar
crypto extension *does* have a schedule-assist pair — `aes64ks1i`/`aes64ks2`
— filling the same role `_mm_aeskeygenassist_si128` does for AES-NI. Per
GCC/Clang's `<riscv_crypto.h>` feature guards, both of those and the
`aes64es`/`aes64esm` round-transform instructions are available under `Zkne`
alone (`aes64ks1i`/`aes64ks2` are gated on `Zkne || Zknd`, `aes64es`/
`aes64esm` on `Zkne`) — the *decryption* instructions
(`aes64ds`/`aes64dsm`/`aes64im`, gated on `Zknd`) are the only ones this
backend doesn't need, since CTR/GCM only ever call the forward cipher, same
as every other backend here — which is why the CPU-capability check above
only tests for `Zkne`, and why `CMakeLists.txt` only enables
`-march=rv64gc_zkne`, not `_zknd`, for this one file. So, like
`aes_core_ni.cpp` and unlike `aes_core_arm.cpp`, this backend hand-rolls its
own schedule rather than sharing `aes_key_schedule.hpp`.

**Inline asm, not `<riscv_crypto.h>` C intrinsics.** The four instructions
(`aes64esm`/`aes64es`/`aes64ks1i`/`aes64ks2`) are emitted as inline asm
(`asm("aes64esm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2))`), not via
`<riscv_crypto.h>`'s `__riscv_aes64esm`-style intrinsics — that header turned
out to be a comparatively recent GCC/Clang addition, present in a current
Homebrew GCC 16 but absent from Ubuntu 24.04's `g++-riscv64-linux-gnu`
package (GCC 13.3), the actual cross-compiler this project's `qemu-riscv64`
CI job uses. This was found the direct way: the intrinsics version was
tried first, broke that CI job on `#include <riscv_crypto.h>: No such file
or directory`, and switching to inline asm (which only needs binutils to
recognize the mnemonics, already true well before GCC grew the intrinsics
header) fixed it without narrowing which toolchains this backend supports.

**The 128-bit AES state/round-key** is represented as a pair of 64-bit
registers (lo = bytes 0..7, hi = bytes 8..15), the layout the ISA's AES
instructions are defined over (RISC-V is little-endian, so a raw 8-byte load
from the block reproduces this layout with no byte-swapping, the same as
x86-64/AArch64's 128-bit vector loads) — each instruction produces only half
the next round's state, so a full round is two calls with the operand order
swapped between them (`aes64esm(lo, hi)` then `aes64esm(hi, lo)`). Both the
round-loop structure and the AES-128/256 key-schedule unrolling in
`aes_core_riscv.cpp` follow OpenSSL's
`rv64i_zkne_encrypt`/`rv64i_zkne_set_encrypt_key`
(`crypto/aes/asm/aes-riscv64-zkn.pl`) — the canonical worked reference for
this extension — rather than being derived from the bare ISA spec, since
getting an unfamiliar extension's instruction sequence right from prose
risks a silently-wrong cipher that only a real KAT run catches; the
sequence was additionally checked by compiling it with a real riscv64 GCC
and inspecting the emitted assembly against that reference pattern.

**Build isolation and CI, same shape as ARM.** `aes_core_riscv.cpp` is the
only file compiled with `-march=rv64gc_zkne`
(`CMakeLists.txt`'s `AESLIB_TARGET_IS_RISCV64` branch) — same isolation
rationale as `-maes`/`-march=armv8-a+crypto`, though note RISC-V's `-march=`
*replaces* rather than extends the base ISA string on GCC/Clang, so this
assumes the `riscv64-linux-gnu` cross toolchain's default `rv64gc` base
(`cmake/riscv64-linux-gnu.cmake`). Two new CI legs test it, mirroring the
arm64 emulated/native pair: `qemu-riscv64` (cross-compiled, run under
`qemu-riscv64-static -cpu max,zkne=true`) and `riscv64-native`, which uses
the [RISE RISC-V
Runners](https://riseproject.dev/2026/03/24/announcing-the-rise-risc-v-runners-free-native-risc-v-ci-on-github/)
free-CI service for real, non-emulated riscv64 hardware (physical Scaleway
EM-RV1 servers, SOPHGO SG2044 chip) — requires installing RISE's GitHub App
on the repo, a one-time manual step outside this codebase.

**A second honest gap, specific to this one CI runner's QEMU package
version.** `qemu-riscv64` needs `zkne=true` (`-cpu max` alone doesn't enable
it — found the direct way, by that job initially failing) to make QEMU's
TCG actually execute the Zkne instructions. But even with that flag,
`cpu::has_hw_aes()` still reports Software under this specific QEMU:
checked directly against QEMU's own source at the exact version Ubuntu
24.04 ships (`qemu-user-static` 8.2.2) and confirmed
`RISCV_HWPROBE_EXT_ZKNE`/`ZKND` don't exist yet as bit definitions in that
version's `riscv_hwprobe()` implementation — no CPU flag can make an
unimplemented bit appear. That's a detection-*reporting* gap in one CI
runner's QEMU package, not a missing-instruction gap (the instructions
really do execute correctly there) and not a bug in this project's own
`riscv_hwprobe()` code. Rather than let it silently skip proving the
backend's real output, `tests/test_aes_core.cpp` gained two riscv64-only
tests (`riscv_hardware_matches_fips197_kat_directly` and the AES-128
equivalent) that call `aes_core_riscv.cpp`'s functions directly, bypassing
`cpu::has_hw_aes()` — so `qemu-riscv64` still exercises and proves the real
instruction sequence every run, even though the ordinary
dispatch-through-`active_backend()` path can't be asserted there.

**An honest gap this backend does not close: silicon crypto-extension
support on the native CI leg is unconfirmed.** The AArch64 Crypto
Extensions have been close to universal on real ARM64 silicon for years,
which is why `linux-arm64-native` asserts `AESLIB_EXPECTED_BACKEND=hardware`
unconditionally. RISC-V's crypto extensions are new, and plenty of shipping
RISC-V server chips implement only the base ISA — whether the SG2044 chip
underlying the RISE runners is one of the exceptions isn't yet established.
`riscv64-native`'s CI job therefore does *not* assert a specific backend;
it proves the build and whichever backend `riscv_hwprobe()` correctly
selects both work on real riscv64 hardware, and leaves "is that backend
Hardware or the Software fallback" for the job's own output to answer,
rather than asserting either way without having actually looked.

### Additional AES modes: AES-128 + AES-GCM

This bonus adds AES-128 key support (alongside the existing AES-256) and
AES-GCM, an authenticated mode, alongside the existing unauthenticated
`Aes256Ctr`. CBC mode was deliberately not implemented (see "Scope
limitations" below).

**A runtime `KeySize` discriminant on `SecretKey`, not a template.** The
obvious alternative was `template <KeySize> class SecretKey` (or a pair of
`SecretKey128`/`SecretKey256` types). Both were rejected: `SecretKey` is
the one type touched by every hardened bonus in this codebase (encrypted
storage, misuse-resistant API, memory protection) — templating it would
force either duplicating that logic per instantiation or threading a
template parameter through every function that takes `const SecretKey&`,
for a blast radius far out of proportion to "the key is sometimes 16 bytes
instead of 32." A runtime `size_` field keeps every existing call site
touched by nothing but the two points that actually need to branch on
size: the block-cipher dispatch and the file-format size marker. `bytes_`
stays a fixed 32-byte array — an AES-128 key only reads/saves its first 16
bytes, and the unused 16 are still genuine CSPRNG output, `mlock`ed and
wiped exactly like the rest.

**Software backend: one template, not a second hand-written cipher.**
`src/aes_core_soft.cpp`'s key-expansion/round-transform code was already
loop-driven over `Nk`/`Nr` rather than unrolled, so it was parameterized as
`template <int Nk, int Nr>`: `aes256_encrypt_block_soft` becomes
`aes_encrypt_block_soft<8, 14>` (confirmed behaviorally identical by the
pre-existing FIPS-197 KAT continuing to pass unchanged), and
`aes128_encrypt_block_soft` is `aes_encrypt_block_soft<4, 10>`. FIPS-197
§5.2's extra `SubWord` step for `Nk > 6` is written as a generic
`i % Nk == 4` branch that's simply never true when `Nk == 4`, so AES-128's
simpler 10-round schedule falls out of the same code with no specialization
needed.

**AES-NI backend: a separate routine, not shared code.** AES-256's
existing key expansion is hand-unrolled around the Nk=8 schedule's
two-word-per-step structure, driven by the fact that
`_mm_aeskeygenassist_si128`'s round-constant argument must be a
compile-time immediate. AES-128's schedule advances one word per step — a
structurally different shape, not a smaller instance of the same one — so
rather than contort the existing macros, AES-128 gets its own
`expand_key128_ni`/`aes128_encrypt_block_ni`, following the standard
`KEY_128_ASSIST` pattern from Intel's AES-NI white paper (Gueron). The
existing AES-256 code is untouched.

**GCM design.** `AesGcm::encrypt()`/`decrypt()` follow NIST SP 800-38D: for
a 96-bit nonce, `J0 = nonce || 0x00000001` (the same nonce||counter
construction `Aes256Ctr` uses, §2), keystream blocks start at counter 2
(counter 1/`J0` is reserved for encrypting the tag), and the tag is
`E(K, J0) XOR GHASH_H(AAD, ciphertext)`. Reserving `J0` means this
construction's per-invocation limit is 2^32-2 blocks, one less than CTR's
2^32. `decrypt()` recomputes the expected tag and compares it via
`detail::constant_time_equal` *before* decrypting — the same
verify-then-decrypt discipline as the encrypted key storage below — so a
tampered ciphertext or tag is rejected without ever running the decrypt
transform on attacker-influenced bytes.

`src/ghash.cpp` implements GF(2^128) multiplication (`gf128_mul`, NIST SP
800-38D Algorithm 1) as a 128-iteration bit-serial shift-and-conditionally-
XOR loop, using a bitmask rather than a branch to fold in each bit of the
secret operand — the same discipline the AES S-box uses, extended here
since both `gf128_mul` operands are secret-derived (the running GHASH
accumulator, and the subkey `H = E(K, 0^128)`). `ghash()` folds
zero-padded 16-byte blocks of AAD, then ciphertext, then a length block
(bit-lengths of AAD and ciphertext, big-endian) into an accumulator per SP
800-38D §6.4. No PCLMULQDQ acceleration is used — GHASH stays portable,
branch-free C++ like the rest of the non-AES-NI code.

GCM vectors were cross-checked against two independent implementations
(Python's `cryptography` and `pycryptodome`), following the same
methodology as `tests/test_reference_vectors.cpp`.

**Scope limitations, stated explicitly:**

- **CBC mode was not implemented.** GCM was chosen instead because it's
  forward-cipher-only — every backend here only ever implements AES
  *encryption*, and GCM's keystream generation is exactly that same
  forward-only operation. CBC *decryption* would require a full AES inverse
  cipher in both backends — real new work — for a mode that's also a
  strict security downgrade from GCM (confidentiality only, no integrity,
  and CBC padding oracles are a well-documented real-world attack class GCM
  avoids by not padding at all). Given a choice between one new mode's
  forward-only cipher work versus another mode's forward-and-inverse work
  for a weaker security property, GCM was the better use of the same
  effort.
- **`Aes256Ctr` now dispatches on key size, same as `AesGcm`.** It kept its
  original name for API stability, but `encrypt_block()` now checks
  `key.size_bytes()` and calls the AES-128 or AES-256 backend accordingly,
  so an AES-128 `SecretKey` works with CTR end to end.
- **The encrypted key-storage format (below) was bumped to version 2** to
  support both key sizes: a 1-byte key-size marker follows the version
  byte, and the wrapped-key field is `key_size` bytes instead of a fixed
  32. The wrapping key derived from the passphrase is still always
  AES-256 regardless of the wrapped key's size. Version 1 is no longer
  accepted — a clean break, since no real persisted files exist outside
  this repo's own tests.

### Safer key storage

`SecretKey::save_to_file_encrypted(path, passphrase, iterations)` /
`load_from_file_encrypted(path, passphrase)` wrap the raw key under a
passphrase-derived key before it ever touches disk, instead of the
plain-bytes `save_to_file()`/`load_from_file()` path.

**Why PBKDF2-HMAC-SHA256 over an OS keystore.** Windows DPAPI and Linux
`libsecret`/keyring were considered first, since the brief calls them out
explicitly, but both were rejected on portability/testability grounds:
DPAPI is Windows-only and user/machine-bound, with no Linux equivalent to
exercise the same code path across this project's CI matrix (native
Linux/Windows/macOS, ASan/UBSan, `qemu-aarch64`, two native ARM64 runners,
two `qemu-x86_64` legs); `libsecret` needs a running D-Bus session and
keyring daemon, unreliable on a headless CI runner. A passphrase+KDF
scheme has no such dependency — it's exercised identically on every
platform this project tests on. This is the same shape as
[age's scrypt recipient](https://c2sp.org/age@v1.1.0) and OpenSSH's
`bcrypt_pbkdf`-wrapped private keys.

**Why PBKDF2-HMAC-SHA256 over Argon2id/scrypt.** OWASP's
[Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
ranks Argon2id first, then scrypt, then bcrypt, and lists PBKDF2 last — "the
preferred algorithm when [FIPS-140 compliance is] required" — so this is
not the highest-security choice available. It was chosen because this
project has zero external dependencies and hand-rolls its own primitives
(AES, CSPRNG) rather than vendoring a crypto library; Argon2id/scrypt are
memory-hard constructions with meaningfully more attack surface to
implement correctly from scratch than PBKDF2-HMAC-SHA256, which reduces to
a well-analyzed HMAC feedback loop ([RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)
§5.2) that's easy to validate against known-answer tests. OWASP's own
recommendation (600,000 iterations) is used as the default
(`kDefaultPbkdf2Iterations`), and NIST SP 800-132's floor (≥1000
iterations, ≥128-bit salt) is met. This is a disclosed
implementation-simplicity tradeoff, not a claim that PBKDF2 is the
strongest available option.

**Wire format** (`src/key_storage.cpp`, version 2, `70 + key_size` bytes —
86 for AES-128, 102 for AES-256 — magic `"AESW"`):

| offset | size | field |
| --- | --- | --- |
| 0 | 4 | magic `"AESW"` |
| 4 | 1 | version (`2`) |
| 5 | 1 | key size marker (`16` or `32`) |
| 6 | 16 | salt (random, 128-bit) |
| 22 | 4 | PBKDF2 iteration count (uint32 LE) |
| 26 | 12 | AES-256-CTR nonce for the wrap |
| 38 | `key_size` | wrapped key ciphertext |
| `38+key_size` | 32 | HMAC-SHA256 tag over bytes `[0, 38+key_size)` |

PBKDF2 derives 64 bytes from `(passphrase, salt, iterations)`: the first 32
become the AES-256-CTR wrapping subkey, the next 32 the HMAC-SHA256 subkey.
The two operations never share key material, so a weakness in one
primitive's use of its key can't be leveraged against the other.

**Encrypt-then-MAC.** This library's AES-256-CTR is unauthenticated by
design (§6) — CTR ciphertext is bit-flip malleable, so wrapping the raw key
with CTR alone would let a corrupted or tampered key file silently decrypt
to garbage with no signal. Per the
[Encrypt-then-MAC](https://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)
principle, an HMAC-SHA256 tag is computed over the plaintext structure and
verified *before* decryption — `load_from_file_encrypted` checks the tag
first, throws `AuthenticationError` on mismatch, and only decrypts if it
matches, so attacker-controlled ciphertext never reaches the decrypt path
when the tag doesn't verify. Tag comparison goes through
`detail::constant_time_equal`, which XORs and accumulates every byte rather
than returning on the first mismatch, to avoid a timing side channel on MAC
verification.

**Hardening against a malicious/corrupted file.** Three issues were found
and fixed during review, and are worth stating as part of the format's
design rather than leaving implicit:

1. `iterations == 0` collapses PBKDF2 to a single HMAC evaluation,
   defeating iteration stretching entirely — rejected on both save
   (`LimitError`) and load (`FormatError`).
2. `load_from_file_encrypted` must run PBKDF2 with the file's own,
   unauthenticated-until-verified iteration count *before* the HMAC tag can
   be checked (verifying the tag needs the MAC subkey, which only PBKDF2
   produces). A hostile file could otherwise claim an enormous iteration
   count and force an unbounded computation before authentication gets a
   chance to reject it. Loading now rejects any count above
   `kMaxPbkdf2Iterations` (50,000,000 — ~80x the default, high enough to
   never reject a legitimate file while bounding worst-case load time to a
   few seconds).
3. A file could instead claim a small-but-nonzero count (e.g. 1), which
   would be accepted and derive the MAC subkey with negligible stretching —
   the same class of bug as
   [FiloSottile/age#417](https://github.com/FiloSottile/age/issues/417) in
   age's scrypt recipient. Both save and load now enforce a floor of
   `kMinPbkdf2Iterations` (1000, NIST SP 800-132's PBKDF2 minimum).

The PBKDF2-derived scratch buffers are wrapped in a `detail::ScopedWipe`
RAII guard rather than relying solely on a manual `secure_wipe()` call
before every return, so an exception thrown partway through (`IoError`/
`FormatError`/`AuthenticationError`) still gets the buffers wiped.

**A measured tradeoff, not a hidden one.** PBKDF2-HMAC-SHA256 at 600,000
iterations is deliberately slow — that's the point. On this project's own
hardware, `save_to_file_encrypted()` at the default iteration count takes
on the order of ~1 second in an optimized build (longer under ASan/UBSan or
emulation), since this is a from-scratch, scalar SHA-256 implementation
computing roughly a million HMAC-SHA256 calls per derivation. `iterations`
is an explicit, overridable parameter for callers (e.g. tests) who need a
faster derivation and can accept a smaller security margin; production
callers should keep the default.

**Threat model.** Protects against: an attacker who obtains the key file
at rest without the passphrase; tampering with or corruption of the key
file (the HMAC tag catches any change); and rainbow-table-style
precomputation across multiple key files (each save generates a fresh
random salt). Explicitly does **not** protect against: a weak or guessable
passphrase; the passphrase being captured via keylogger, shoulder-surfing,
or a compromised input path; a GPU/ASIC-equipped attacker, against whom
PBKDF2's lack of memory-hardness makes it weaker than Argon2id/scrypt at
the same wall-clock cost; a live attacker with access to the process while
the key is resident in memory (the same caveat "Minimizing key exposure in
memory" below states); and this is not hardware- or account-bound the way
DPAPI or a TPM-sealed key would be — anyone with the passphrase can decrypt
the file on any machine.

Design references: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
(iteration default), [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
(iteration/salt floor), [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)
(PBKDF2), [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)/FIPS 198-1
(HMAC) and FIPS 180-4 (SHA-256) — both implemented from scratch and checked
against [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)'s HMAC-SHA256
and [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html) Appendix
A's PBKDF2-HMAC-SHA256 test vectors in `tests/test_key_storage.cpp` (not
just round-trip self-tests, which can't catch an internally consistent but
wrong implementation).

### Key generation ergonomics

`SecretKey`'s API is designed so a caller has to work to misuse it, rather
than relying on documentation to warn them off:

- **Named factories, no public default state.** `generate()` and
  `load_from_file()` are the only ways to obtain a `SecretKey`; the default
  constructor is private, so there's no way to end up holding a
  default-constructed, all-zero "key" that looks valid but isn't. Both
  factories are `[[nodiscard]]`, turning a stray `SecretKey::generate();`
  with the result thrown away into a compiler warning instead of a
  silently-generated-and-destroyed key.
- **Move-only and `final`.** Copy is `= delete`d, and the class is marked
  `final` — it hand-manages a wipe/lock resource in its special members,
  and disallowing derivation closes off lifetime/slicing misuse a subclass
  could otherwise introduce.
- **No public raw-byte accessor.** The class used to expose a public
  `bytes()` returning `const std::array<std::byte, 32>&` — a real footgun:
  any caller, not just the AES backends that actually need raw access for
  key expansion, could copy it into a plain local (escaping wipe/`mlock`
  entirely) or log it accidentally. `bytes()` was removed and replaced with
  `aeslib::detail::key_bytes()`, a `friend` free function reachable only
  from `.cpp` files that `#include "src/internal.hpp"` — i.e. the two AES
  backends and the test suite. An external caller linking against the
  public `include/aeslib/` headers has no way to read, copy, or print raw
  key bytes at all; the only sanctioned way to get key material out is the
  explicit `save_to_file()`.

This follows the SEI CERT C++ rule against returning references to a member
less accessible than intended, the design principle behind NaCl's API
(identified as the least misuse-prone crypto library in a comparative
study — raw key bytes shouldn't be accepted or returned by anything except
the code that constructs/consumes the key type), and the same idea Rust's
[`secrecy`](https://docs.rs/secrecy) crate applies via `Secret<T>`/
`ExposeSecret`: one explicit, narrow, auditable access path instead of an
ordinary public getter.

### Minimizing key exposure in memory

Four techniques address the raw key, its most sensitive derivative, and the
file-I/O path key bytes travel through — informed by how libsodium's
`sodium_mlock`/`sodium_memzero`, OpenSSL's `OPENSSL_cleanse`, and Bitcoin
Core's locked-memory allocator handle the same problem:

- **Wipe on destruction/move.** `SecretKey::wipe()` zeroes the backing
  buffer via a `volatile` reference loop, not a plain `std::fill`/`= {}`. A
  non-`volatile` zero write immediately before the buffer goes out of scope
  is a dead store the optimizer is entitled to delete, since nothing else
  observably reads the memory again; `volatile` forces the write to
  happen. This is the same effect `explicit_bzero`/`memset_s`/
  `SecureZeroMemory` achieve by other means (`explicit_bzero` isn't used
  directly since it isn't in the C++17 standard library or universally
  available); OpenSSL's `OPENSSL_cleanse` uses a `volatile` function
  pointer to `memset` instead, called indirectly, to the same end.
- **Swap and core-dump protection.** The constructor `mlock()`s (POSIX) or
  `VirtualLock()`s (Windows) the key's backing pages, pinning them in RAM
  and excluding them from swap/pagefile; `wipe()` calls the matching
  `munlock()`/`VirtualUnlock()` right after zeroing. On Linux,
  `lock_memory()` additionally calls `madvise(MADV_DONTDUMP)` (and
  `unlock_memory()` the complementary `MADV_DODUMP`), since `mlock()` says
  nothing about core dumps by itself — a page can be locked in RAM *and*
  written into a crash-triggered core file. There's no BSD/macOS
  equivalent, so this half is Linux-only. The move constructor/assignment
  re-lock the relocated destination and unlock the vacated source, so a
  moved-from `SecretKey` never keeps its old storage pinned or
  dump-excluded. `mlock`/`madvise`/`VirtualLock`'s return value is
  deliberately ignored — `mlock` can fail without `CAP_IPC_LOCK` or a
  sufficient `RLIMIT_MEMLOCK` (the default in many containers), and this is
  defense-in-depth layered on the wipe/non-copy guarantees, not something
  key generation should hard-fail over. Verified directly: the harness
  under `ulimit -l 0` still succeeds, and a Linux-only test reads
  `/proc/self/status`'s `VmLck` field to confirm the lock takes effect when
  the platform allows it, without failing the suite when it doesn't.
  **Windows caveat:** `VirtualLock` is weaker than POSIX `mlock` — it pins
  pages into the process's working set, but Windows can still page them out
  once the process has no thread scheduled to run, which `mlock` does not
  do. `CryptProtectMemory` (DPAPI) would be a stronger alternative
  (encrypts in place with a kernel-held, per-boot key, also keeping it out
  of user-mode crash dumps), but isn't used here in order to keep the
  locking code path uniform across platforms; it's the documented next step
  if Windows-specific hardening mattered more than portability.
- **Avoiding unnecessary copies in the file-I/O path.**
  `save_to_file()`/`load_from_file()` write/read key bytes through raw
  `write(2)`/`read(2)` (POSIX) or `WriteFile`/`ReadFile` (Windows), not
  through `std::ofstream`/`std::ifstream` — an iostream sink/source copies
  through its own internal `streambuf`, an incidental unwiped extra copy
  that neither `wipe()` nor `mlock()` ever touches.
- **Wiping the derived key schedule, not just the key.** Both AES backends
  expand the raw key into a full round-key schedule once *per 16-byte
  block* (CTR calls the block cipher once per keystream block), so the
  schedule spends far more aggregate time sitting unwiped in stack memory
  than the key itself ever does — a gap a wipe-only-the-key approach would
  miss. Both software and AES-NI backends zero their local `schedule` array
  (same volatile-write technique) immediately after the last round that
  consumes it. The schedule isn't `mlock`ed — it's stack-resident and
  short-lived enough (one block's worth of encryption) that the
  cost/benefit favors just wiping it promptly.

**Threat model.** Protects against: key or schedule bytes surviving,
readable, past their logical lifetime in a stack/heap dump taken after the
owning object/frame is gone; key material written to swap/the pagefile
while a `SecretKey` is alive; key material in a Linux core dump taken while
a `SecretKey` is alive; incidental copies left in iostream buffer memory;
and accidental duplication via the API surface. Explicitly does **not**
protect against: inspecting a still-*live* process (an attached debugger,
`ptrace`, or a core dump taken while a `SecretKey`/schedule is still in
scope — raw bytes are necessarily resident as ordinary memory while
actually being used; avoiding that entirely is the "far end of the
spectrum" the brief calls out — hardware enclaves, an HSM, or never
materializing the key outside a keystore process — and isn't attempted
here); an attacker with root/kernel privileges; `mlock`/`VirtualLock`/
`madvise` failing silently on a host with a tight memlock limit (an
accepted tradeoff); a cold-boot attack (DRAM/SRAM retain contents for
seconds to minutes after power loss, letting an attacker with physical
access dump pre-boot RAM regardless of `mlock`/wipe-on-destruction, which
only govern the process's logical key lifetime, not what's electrically
still in the DIMM); whole-system hibernate-to-disk bypassing `mlock`; or
side channels beyond the constant-time software S-box already addresses.
Safer key *storage* is the separate bonus above.

Design references: [Libsodium: Secure memory](https://libsodium.gitbook.io/doc/memory_management)
(`sodium_mlock`/`sodium_memzero`, the direct model here); [OpenSSL
`crypto/mem_clr.c`](https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c)
(`OPENSSL_cleanse`'s alternative compiler-barrier technique); [Bitcoin Core
PR #15600](https://github.com/bitcoin/bitcoin/pull/15600) (the same
`mlock`/`MADV_DONTDUMP` gap, in a production codebase); ["VirtualLock only locks
your memory into the working set"](https://devblogs.microsoft.com/oldnewthing/20071106-00/?p=24573)
(the Windows caveat above); [`CryptProtectMemory`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)
(the road not taken, and why); ["Lest We Remember: Cold-Boot Attacks on
Encryption Keys"](https://cacm.acm.org/research/lest-we-remember/) (the
cold-boot/DRAM-remanence entry in the threat model).

### Generic support for other types via templates

Before this bonus, `Aes256Ctr::encrypt`/`decrypt` and `AesGcm::encrypt`/
`decrypt` were fixed to `std::vector<std::byte>` on the plaintext side.
That signature stays exactly as it was — the baseline the challenge asks
to keep — but both classes now also accept, and can decrypt into, any type
whose storage can be safely viewed as raw bytes.

**Why C++17 SFINAE, not C++20 concepts.** `CMakeLists.txt` sets
`CMAKE_CXX_STANDARD 17`, and nothing else in this codebase assumes C++20,
so this bonus stays on C++17 rather than quietly raising the project's
language requirement for one feature. That rules out `std::span`'s
`as_bytes()`/`as_writable_bytes()` (the standard-library version of exactly
this idea) and `concept`/`requires`. The C++17 equivalent is a set of
`std::void_t` detection traits plus `std::enable_if_t`, in the new
`include/aeslib/byte_view.hpp`.

**Two shapes a type can be byte-viewable as.** The brief distinguishes
"other byte containers (`std::array`, `std::span`, etc.)" from "any type at
all, ... via its size and a reinterpreted view of its memory" — genuinely
different operations, so `byte_view.hpp` keeps them as two separate traits:

1. **Byte-container** (`is_byte_container<T>`): `T` exposes `.data()`,
   `.size()`, and `T::value_type` (via the `std::void_t` idiom), and
   `T::value_type` is `std::is_trivially_copyable`. Conversion walks the
   container element-wise:
   `reinterpret_cast<const std::byte*>(value.data())` for
   `value.size() * sizeof(value_type)` bytes. Covers
   `std::vector<std::byte>` (the baseline — the exact non-template overload
   always wins for it, see below), `std::vector<std::uint8_t>`,
   `std::array<std::byte, N>`, `std::string`, and — since the brief says
   "any type at all" — containers of any trivially copyable element:
   `std::vector<std::int32_t>`, `std::array<float, N>`, etc.
2. **Byte-object** (`is_byte_object<T>`): `T` is `std::is_trivially_copyable`
   as a whole, and is *not* itself a byte-container. Conversion reinterprets
   the single object: `reinterpret_cast<const std::byte*>(std::addressof(value))`
   for `sizeof(T)` bytes. This is the "any type at all" case for
   non-container types — a plain struct is treated as one opaque blob.

The `!is_byte_container<T>::value` guard on `is_byte_object` matters:
`std::vector<int32_t>` isn't trivially copyable as a whole (it owns a heap
buffer), so it only satisfies the container trait — but `std::array<int,
4>` *is* trivially copyable as a whole, and without the guard would satisfy
both traits simultaneously. Making them mutually exclusive means every
byte-viewable type has exactly one, unambiguous conversion path, rather
than an implementation-detail tiebreak between "4 ints, converted
element-wise" and "16 bytes of one opaque blob" (the two happen to produce
identical bytes today, but a reader shouldn't have to notice that to trust
the behavior is well-defined).

**What `decrypt_as<T>` requires on the way back.** `from_byte_vector<T>`
validates before reinterpreting, rather than reading past a short buffer:

- **Resizable container** (`.resize(std::size_t)` detected via SFINAE —
  `std::vector`, `std::string`): the decrypted byte count must be a whole
  multiple of `sizeof(value_type)` (`FormatError` otherwise), and the
  result is resized to fit exactly.
- **Fixed-capacity container** (`std::array<X, N>`, or any type without
  `resize`): capacity can't change, so the byte count must equal
  `N * sizeof(X)` exactly (`FormatError` otherwise).
- **Byte-object**: the byte count must equal `sizeof(T)` exactly
  (`FormatError` otherwise).

`decrypt_as<T>` is a new name, not an overload of `decrypt`, because the
return type can't be deduced from the call's arguments the way the
parameter type drives overload resolution for `encrypt` — a caller writes
`decrypt_as<T>(key, container)` to say which `T` they want.

**Why `std::is_trivially_copyable` is necessary but not sufficient.** The
trait only encodes what the *language* guarantees — that copying an
object's representation byte-for-byte and copying the object itself have
the same observable effect. It says nothing about whether those bytes mean
anything outside the process that produced them: a struct holding a raw
pointer, or a `std::variant` whose active member happens to be
pointer-shaped, can be trivially copyable and still produce bytes that are
meaningless, or alias unrelated memory, once written to a file and read
back elsewhere. C++17 has no reflection to reject "trivially copyable but
semantically unsafe" types automatically, so this is a documented caller
responsibility — the trait rules out non-trivially-copyable types
(`std::string`-holding structs, anything with a user-defined copy
constructor or virtual functions), but is not a proof that a given `T` is
*meaningful* to persist. In practice: prefer plain-old-data structs of
fixed-width integers, floats, and byte arrays, and avoid pointers,
references, or handles inside a type passed to `encrypt`/`decrypt_as`.

**Scope.** This extends `Aes256Ctr::encrypt`/`decrypt_as` and
`AesGcm::encrypt`/`decrypt_as` — the plaintext side only. `AesGcm`'s `aad`
parameter stays `std::vector<std::byte>`; templating a secondary,
usually-empty parameter too would double the type parameters for little
benefit. `Container`/`GcmContainer` serialization and `read_file`/
`write_file` already operate on bytes and are unaffected.

### Foreign-language interface

The rest of this library's public surface is ordinary modern C++ —
`std::vector<std::byte>`, `std::filesystem::path`, exceptions, templates —
none of which is callable from another language: C++ name mangling means
even the names aren't resolvable without a demangler agreeing with this
compiler's ABI, exceptions unwinding across a language boundary are
undefined behavior, and STL container layouts aren't a stable ABI.
`include/aeslib/capi.h` / `src/capi.cpp` add a second, deliberately
narrower public surface — plain C, `extern "C"` linkage, built as a shared
library (`aeslib_c`) — specifically to be loadable from something other
than this same C++ toolchain.

**Opaque handle, not an exposed struct.** `aeslib_key_t` is `typedef struct
aeslib_key* aeslib_key_t`, where `struct aeslib_key { aeslib::SecretKey
key; }` is defined only inside `capi.cpp` — the public header never sees
`SecretKey`'s layout. This is the standard PImpl-via-C-handle pattern: the
handle's *identity* is public, its *representation* isn't, so the C++ side
can keep changing `SecretKey`'s internals (as the bonuses above already
have, repeatedly) without the C ABI's binary layout ever needing to match.

**Status codes, not exceptions, cross the boundary.** Every function that
can fail returns `aeslib_status`, mapping 1:1 onto this project's exception
hierarchy (`IoError`→`AESLIB_ERR_IO`, `FormatError`→`AESLIB_ERR_FORMAT`,
`LimitError`→`AESLIB_ERR_LIMIT`, `AuthenticationError`→
`AESLIB_ERR_AUTHENTICATION`, plus `AESLIB_ERR_INVALID_ARGUMENT` for a
null/malformed argument caught before any C++ call, and
`AESLIB_ERR_UNKNOWN` as a catch-all). `aeslib_last_error_message()` returns
the underlying exception's `what()`, kept in a thread-local `std::string`
so concurrent callers on different threads don't clobber each other.
Every exported function is a `try { ... } catch (...) { return
translate_exception(); }`, with `translate_exception()` re-throwing into a
`catch` chain ordered most-derived-first — the one non-negotiable rule at
this boundary: a C++ exception unwinding into a non-C++ caller (or even
different C++ code with an incompatible exception ABI) is undefined
behavior, not a caught-and-reported error.

**Fixed arrays for fixed-size data, heap buffers + an explicit free
function for the rest.** The CTR nonce (12 bytes) and GCM tag (16 bytes)
are already compile-time-constant sizes in the C++ layer; `capi.h`
duplicates them as `AESLIB_NONCE_BYTES`/`AESLIB_TAG_BYTES` defines (a plain
C header can't `#include` the C++ originals), with a `static_assert` on
each side catching drift. Callers pass a stack array for these. Ciphertext/
plaintext, whose length depends on the input, are different: `capi.cpp`
allocates (`new uint8_t[n]`) and hands back a pointer plus length, and the
only sanctioned release is `aeslib_buffer_free()` — never the caller's own
`free()`/`delete[]`. This sidesteps the allocator-boundary pitfall where a
shared library and its caller are linked against different allocators
(most concretely on Windows, where a DLL built against one CRT and an
EXE/interpreter against another have genuinely separate heaps).

**Symbol visibility.** `aeslib_c` is built with `CXX_VISIBILITY_PRESET
hidden` plus an explicit `AESLIB_C_API` export macro on every function in
`capi.h`, so only the intended `aeslib_*` symbols are part of the shared
library's exported surface — a deliberate, minimal surface a consumer can
treat as stable across a rebuild.

**Why a shared library.** The core `aeslib` target is a static archive —
fine for a C++ consumer, but a non-C++ runtime needs something it can
`dlopen()`/`LoadLibrary()` at run time. `aeslib_c` (`SHARED`) links the
static archive in, which on Linux/macOS requires every object file in it to
be position-independent —
`set_target_properties(aeslib PROPERTIES POSITION_INDEPENDENT_CODE ON)`
was added for exactly this.

**Deliberately out of scope: passphrase-wrapped key storage.**
`save_to_file_encrypted`/`load_from_file_encrypted` are not exposed through
the C ABI. This bonus's surface is the minimal set that demonstrates the
pattern end to end (key lifecycle, both cipher modes, error propagation),
not a mechanical re-export of the entire C++ API; extending `capi.h` with
those two functions would be a straightforward follow-up with no new design
questions.

**Testing across the boundary.** `bindings/python/` is the required
minimal example of calling this library from another language:
`aeslib_ffi.py` is a `ctypes` wrapper with explicit `argtypes`/`restype` on
every exported function (ctypes performs no automatic signature checking —
a wrong or missing declaration is a silent memory-corruption bug, the
Python-side analogue of the "no undefined behavior" requirement elsewhere
in this brief), and `demo.py` round-trips AES-256-CTR and
AES-256-GCM-with-AAD through the C ABI, then deliberately tampers with a
GCM tag and asserts it comes back as `AESLIB_ERR_AUTHENTICATION` — a
negative-path test, not just happy-path. It's registered as the
`aeslib.capi_python` CTest test, so it runs on every `ctest` invocation
alongside the C++ suites.

**Sanitizer-build notes.** Running this test under
`-DAESLIB_ENABLE_SANITIZERS=ON` needed two fixes, both scoped to this one
test's CI environment rather than the library itself:

- ASan needs to be the first thing loaded into a process, and Python's
  `ctypes.CDLL()` loading an ASan-instrumented `aeslib_c` into an
  already-running, non-ASan `python3` is exactly the case ASan's own
  diagnostics warn about. `CMakeLists.txt` preloads ASan's runtime into
  `python3` first (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on
  macOS), a standard technique for testing ASan-built Python C extensions.
  On macOS specifically, a framework-build `python3` is a shim that
  re-execs the real interpreter via `posix_spawn`, dropping
  `DYLD_INSERT_LIBRARIES` before `ctypes.CDLL()` ever runs — a documented
  issue ([tobywf.com](https://tobywf.com/2021/02/python-ext-asan/),
  [jonasdevlieghere.com](https://jonasdevlieghere.com/post/sanitizing-python-modules/)),
  fixed by preloading against the unshimmed interpreter binary bundled at
  `.../Resources/Python.app/Contents/MacOS/Python` instead, which
  `CMakeLists.txt` locates by walking up from `Python3_EXECUTABLE`
  (falling back to a warn-and-skip if none is found).
- On Linux CI, LeakSanitizer flags ~121 KB of allocations at process exit
  that all bottom out in CPython internals (`Py_InitializeFromConfig`,
  `_ctypes`), never in `capi.cpp` or any `aeslib` symbol — a known
  false-positive shape ([python/cpython#135618](https://github.com/python/cpython/issues/135618)):
  CPython deliberately never frees many internal structures on shutdown,
  which is correct interpreter behavior but exactly what LeakSanitizer
  flags. The fix, per
  [Clang's LeakSanitizer docs](https://clang.llvm.org/docs/LeakSanitizer.html),
  is `ASAN_OPTIONS=detect_leaks=0`, set on `aeslib.capi_python`'s
  `ENVIRONMENT` on both platforms. This disables leak detection for this
  one test only — ASan's memory-safety checks stay on, and it has zero
  effect on the `aeslib_tests`/`aes_harness` runs, which never touch the
  Python interpreter.

Design references: [Nibble Stew: "Exposing a C++ library with a stable
plain C API"](https://nibblestew.blogspot.com/2016/11/exposing-c-library-with-stable-plain-c.html?m=1)
and [ecmwf/odc's API design notes](https://github.com/ecmwf/odc/blob/1.4.1/docs/content/implementation/api-design.rst)
(the opaque-handle/status-code shape); [Python `ctypes`
documentation](https://docs.python.org/3/library/ctypes.html) (the source
for `aeslib_ffi.py`'s explicit type declarations and the
buffer-ownership-crosses-with-the-allocator principle);
[google/sanitizers#796](https://github.com/google/sanitizers/issues/796)
(the general "ASan must load first" constraint this bonus's Python testing
ran into).

## Randomness

Keys and nonces are generated via the OS's native CSPRNG (`BCryptGenRandom`
on Windows, `getrandom(2)` on Linux, `arc4random_buf` elsewhere) — never
`rand()`, `std::mt19937`, or any other non-cryptographic PRNG.
