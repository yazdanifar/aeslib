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
  aes_core_soft.cpp      portable AES forward cipher (FIPS-197), no
                         intrinsics, used as the fallback
  aes_core_ni.cpp        AES forward cipher using AES-NI intrinsics
                         (amd64), used when the CPU supports it
  aes_core_arm.cpp        AES forward cipher using AArch64 Crypto
                         Extensions intrinsics (arm64), used when the CPU
                         supports it (bonus 3.2)
  aes_core_hw.cpp         the one file that knows there's more than one
                         hardware backend — arch-neutral aesNNN_..._hw()
                         wrappers CTR/GCM call instead of _ni/_arm directly
  aes_key_schedule.hpp    shared FIPS-197 key-expansion template, used by
                         both aes_core_soft.cpp and aes_core_arm.cpp
  cpu_detect.cpp          runtime hardware-AES capability check (CPUID on
                         amd64; HWCAP/sysctl/IsProcessorFeaturePresent on
                         arm64, depending on OS)
  csprng.cpp              OS CSPRNG wrapper
  key.cpp, container.cpp  key/container (de)serialization and file I/O
  internal.hpp             shared declarations, not part of the public API
main.cpp                end-to-end harness (see README.md)
```

## Hardware/software dispatch

`aeslib::active_backend()` runs a hardware-capability check the first time
it's called and memoizes the result in a function-local static — so the
decision is made once, at runtime, on whatever machine the binary happens to
be running on. It is never baked in via `#ifdef __AES__` or `-march=native`;
the same compiled binary takes the hardware path on a capable host and the
software path on one without, which is what lets one binary be correct on
both. What that check actually is depends on the build's target
architecture — `CPUID.1:ECX.AESNI` (bit 25) on amd64, or one of three
OS-specific reads of the AArch64 Crypto Extensions feature bit on arm64
(bonus 3.2, see below) — but the caller-facing shape is identical either way:
`cpu::has_hw_aes()` returns one bool, `active_backend()` turns that into
`Backend::Hardware`/`Backend::Software`. `Aes256Ctr`/`AesGcm` call
`active_backend()` internally to pick which block-encrypt function to call;
callers of the public API never see this decision, but it's exposed as a
free function so tests/diagnostics can observe (and the `main.cpp` harness
prints) which path actually ran.

Each hardware backend's intrinsics live in their own translation unit
(`aes_core_ni.cpp` for AES-NI, `aes_core_arm.cpp` for AArch64 Crypto
Extensions) and are the *only* files compiled with an architecture-specific
flag (`-maes` / `-march=armv8-a+crypto` on GCC/Clang, see `CMakeLists.txt`);
every other file — including the CTR/GCM drivers that call into them —
stays free of any architecture-specific instruction set flags. That's what
makes it safe to ship as one portable binary: the compiler never emits a
hardware-AES instruction outside those two files, and each is only ever
*called* after `cpu::has_hw_aes()` has confirmed the corresponding
instructions are safe to execute on this machine.

Because there are now two possible hardware backends but never more than one
real at once in a given build, `aes_core_hw.cpp` is the single seam that
knows this: it exposes arch-neutral `aesNNN_encrypt_block_hw()` wrappers,
implemented purely as `#if`/`#elif` on the target architecture (x86 → `_ni`,
arm64 → `_arm`, anything else → throws). `aes256_ctr.cpp`/`aes_gcm.cpp` call
only `_hw`, never `_ni`/`_arm` by name — so `Aes256Ctr`/`AesGcm` needed
*zero* code changes to gain ARM support beyond that one wrapper file. See
"ARM AArch64 Crypto Extensions (bonus 3.2)" below for what that unlocked.

Because CTR mode only ever needs the forward AES transform (see below),
all backends implement encryption only — there is no AES decryption
routine anywhere in this codebase.

### How the dispatch is verified

2.2 requires that the *same binary* be correct on a machine with hardware AES
acceleration and one without. This is verified on every push by
`.github/workflows/ci.yml` rather than resting on a one-off manual session:

1. `linux-x86_64` builds and tests natively on a GitHub-hosted runner (real
   AES-NI hardware — confirmed `Hardware` in the harness output) and uploads
   the compiled `aeslib_tests`/`aes_harness` binaries as an artifact.
2. `qemu-aes-on` downloads that *exact same artifact* and runs it under
   `qemu-x86_64-static -cpu Westmere` (an AES-NI-capable model).
   `qemu-aes-off` runs the *same artifact* under `-cpu Nehalem` (predates
   AES-NI). `tests/test_backend.cpp` asserts `active_backend()` matches
   what each CPU model should produce via the `AESLIB_EXPECTED_BACKEND` env
   var — one test binary, one build, two CPU identities, two different
   correct outcomes. This is brief 2.2's requirement made literal rather
   than approximated by building twice.
3. `linux-aarch64-cross-build` cross-compiles for a genuinely different
   architecture and uploads that binary; `qemu-aarch64-crypto-on`/
   `qemu-aarch64-crypto-off` run it under `qemu-aarch64-static -cpu max`
   (Crypto Extensions present) and `-cpu cortex-a57` (absent) respectively —
   the same same-binary-two-CPU-identities pattern as `qemu-aes-on`/`-off`,
   now exercising `aes_core_arm.cpp`'s real implementation under emulation
   rather than the throwing stub the pre-bonus-3.2 version of this codebase
   compiled but never called.
4. `macos-arm64` (`macos-14`, real Apple Silicon) and `linux-arm64-native`
   (`ubuntu-24.04-arm`, a real Arm-hosted Linux runner) build and test
   natively — no cross toolchain, no emulation — on two different genuine
   ARM64 machines, both expected to report `Hardware` unconditionally. These
   complement, not replace, the QEMU jobs: QEMU proves dispatch/correctness
   under a *controlled, togglable* CPU model; these two prove the same code
   behaves correctly on *real* silicon, which QEMU's TCG can't fully stand
   in for (see the limitation noted below).

Before writing the amd64 jobs, the core premise — that `qemu-x86_64 -cpu
<model>` actually controls what a guest binary's `CPUID` instruction
reports, rather than passing through the host's real capabilities — was
verified directly against GitHub's runners: probing with `-cpu Westmere`,
`-cpu Nehalem`, `-cpu max`, and `-cpu max,-aes` produced AES-NI
`yes`/`yes`/`yes`/`no` respectively, exactly as expected.

**Limitation worth stating plainly:** QEMU's TCG will generally still
*execute* an `aesenc` (or `AESE`/`AESMC`, on the aarch64 legs) instruction
even when the CPUID/HWCAP feature bit is masked off — real silicon would
`SIGILL`. So `qemu-aes-off`/`qemu-aarch64-crypto-off` prove that (a)
detection correctly reports hardware AES as absent under that model, and (b)
the software path each falls back to is byte-correct — they do not prove
that dispatch would crash safely-versus-silently-corrupt if the hardware
branch were ever taken on real hardware genuinely lacking the extension by
mistake. That gap is closed by the dispatch logic itself (a handful of `#if`
branches in `cpu_detect.cpp`, each reading one OS-provided capability flag)
being simple enough to read completely; it is not closed by execution — which
is exactly why the two native-hardware jobs (`macos-arm64`,
`linux-arm64-native`) matter too: they run the real detection code against
real silicon, not an emulator's approximation of it.

A standalone known-answer test (FIPS-197 Appendix C.3, AES-256) is also run
directly against `aes256_encrypt_block_hw()` and `aes256_encrypt_block_soft()`
in `tests/test_aes_core.cpp`, confirming both produce the exact published
ciphertext block for the same key/plaintext — i.e. whichever hardware
backend the build targets doesn't just "work" on its own, it agrees with the
software backend and with the published test vector, on every CI run
(including the new ARM legs).

### Constant-time software S-box

A textbook software AES implementation typically substitutes bytes via
`kSBox[secret_byte]` — a lookup table indexed by key- and state-dependent
data. That's a classical cache-timing side channel (Bernstein-style): which
cache line the lookup touches depends on the secret byte, and that's
observable by another process on the same core. Neither hardware backend
has this problem (`aesenc` and `AESE`/`AESMC` are both constant-time by
construction), but the software fallback used to have it, silently, on any
host without hardware AES acceleration.

`src/aes_core_soft.cpp`'s `ct_sbox()` replaces the table with a computed
substitution: GF(2^8) multiplicative inversion via a fixed left-to-right
square-and-multiply chain to the 254th power (`x^-1 == x^254` for `x != 0`,
and `0^254 == 0` matches the S-box's own `0 -> 0` convention), followed by
the standard FIPS-197 §5.1.1 affine bit transform. The exponent 254 is a
compile-time constant, so the *sequence* of squarings/multiplications is
identical for every input — no branch anywhere in the computation depends on
the secret byte's value, only branch-free bit-masking (`gmul`'s
`mask = -(b & 1)` pattern) touches it. The affine step is pure bit rotation
and XOR on the byte already in hand, never table-indexed. `sub_bytes()` (the
per-block SubBytes step) and `sub_word()` (used by the Nk=8 key schedule)
both route through this same function, so neither the round transform nor
the key expansion touches a secret-indexed table anywhere in this codebase's
software path. Correctness of the rewrite is checked exhaustively — not just
via the FIPS-197 KAT — by `tests/test_aes_core.cpp`'s
`ct_sbox_matches_canonical_table_exhaustively` test, which compares
`ct_sbox(b)` against the textbook 256-entry S-box table for every possible
byte value (that table is test-only data; it does not exist anywhere in
production code).

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

**Why the test suite doesn't include published CTR test vectors — and what
stands in for them:** NIST SP 800-38A's CTR vectors (F.5.5/F.5.6) use a
free-running 128-bit counter block with no separate nonce field, whereas this
library splits that same 128 bits into a 96-bit random nonce and a 32-bit
counter (the construction above). The published vectors therefore don't
apply directly to this format. Correctness is anchored at three levels
instead: the block-cipher layer, checked in `tests/test_aes_core.cpp`
against four independent AES-256 ECB known-answer vectors (FIPS-197
Appendix C.3, NIST SP 800-38A F.1.5, and two NIST CAVP all-zero/all-ones
edge cases — the latter pair exercises GF(2^8) arithmetic's identity and
max-value corners, which the two "normal" vectors don't touch), plus an
exhaustive check of `ct_sbox()` against the textbook S-box table for all 256
byte values; CTR-level tests in `tests/test_ctr.cpp` covering round-trips,
nonce freshness, wrong-key decryption, correct counter increment across
multiple blocks, the counter-overflow guard at and beyond its exact
boundary, and CTR's expected bit-flip malleability (flipping one ciphertext
bit flips exactly the corresponding plaintext bit — demonstrating *why* the
"no authentication" limitation below is real, not theoretical); and —
filling the gap the missing published CTR vectors leave —
`tests/test_reference_vectors.cpp`, which hardcodes seven AES-256-CTR
ciphertexts for this exact nonce||counter construction (single-block,
multi-block, a partial final block, all-zero and all-ones key/nonce/data,
and single-byte input) computed independently via Python's `cryptography`
library and cross-checked against the `openssl enc -aes-256-ctr` CLI (both
credible, widely-used implementations, neither of which is this codebase).
That file documents exactly how each vector was generated so it can be
reproduced or extended.

The 32-bit counter caps a single message at 2^32 blocks (64 GiB) before the
counter would wrap and start reusing keystream within that one message; not a
concern for the sizes this library is meant for, but it's enforced, not just
documented — `Aes256Ctr::encrypt()`/`decrypt()` call
`detail::validate_block_count()` first and throw `LimitError` rather than
silently wrapping if a caller ever hands them more than that. The check
takes a size, not a buffer, so `tests/test_ctr.cpp` can exercise the exact
boundary without allocating a real 64 GiB vector.

**Why nonce reuse is strictly worse under GCM than under CTR.** `AesGcm`
(see "Additional AES modes" below) uses this exact same nonce||counter
construction for its keystream, plus a GHASH-based authentication tag. Under
plain CTR, reusing a (key, nonce) pair leaks the XOR of the two plaintexts —
bad, but limited to confidentiality. Under GCM, reusing a (key, nonce) pair
is worse in kind, not just degree: Joux's "forbidden attack" shows that two
ciphertexts authenticated under the same (key, nonce) let an attacker solve
a low-degree polynomial equation over GF(2^128) for the GHASH subkey `H`
itself, since `H` is a fixed, key-derived constant that appears identically
in both tags' GHASH computation. Once `H` is recovered, the attacker can
forge a valid authentication tag for *any* ciphertext of their choosing under
that key — not just replay or bit-flip an existing message, but construct
new ones the receiver will accept as authentic. The 2016 "Nonce-Disrespecting
Adversaries" survey found this wasn't theoretical: real HTTPS servers were
found reusing GCM nonces in practice, most from buggy random-nonce generation
colliding at lower-than-expected rates or from counter state not being
carried correctly across process restarts/failover. `AesGcm::encrypt()`
generates a fresh random 96-bit nonce per call from the OS CSPRNG (same
source, same birthday-bound reasoning as `Aes256Ctr::encrypt()` above) for
exactly this reason — a random nonce still has the same 2^48-ish birthday
bound as CTR's, but the consequence of a collision, should one ever occur,
is qualitatively worse for GCM than for CTR.

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

GCM ciphertext container (`.aesg`, see "Additional AES modes" below), all
integers little-endian — a distinct magic from the CTR container's `"AESC"`
so the two file types can't be confused with each other:

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
POSIX. (Version 1, predating AES-128 support, had no size marker and always
wrote 32 bytes; see "Additional AES modes" below for why it was bumped
rather than kept compatible.)

All formats carry an explicit version byte specifically so a future format
change (e.g. a different nonce size) can be introduced without breaking the
ability to read files written by an older version of the library — a reader
can branch on the version byte before interpreting the rest of the layout.

## Key handling

`SecretKey` is move-only — copying is disabled at the type level, so a key
can't be accidentally duplicated by value — and every consumer in this
codebase (`aes256_ctr.cpp`, both AES backends) takes it by `const&`, so no
incidental copies of the raw key exist anywhere in the library.

### Safer key storage (bonus 3.4)

`SecretKey::save_to_file_encrypted(path, passphrase, iterations)` /
`SecretKey::load_from_file_encrypted(path, passphrase)` wrap the raw key
under a passphrase-derived key before it ever touches disk, instead of the
plain-bytes `save_to_file()`/`load_from_file()` path.

**Wire format** (`src/key_storage.cpp`, fixed 101 bytes, magic `"AESW"`,
distinct from the ciphertext container's own format so the two file types
can't be confused):

| offset | size | field |
| --- | --- | --- |
| 0 | 4 | magic `"AESW"` |
| 4 | 1 | version (`1`) |
| 5 | 16 | salt (random, 128-bit) |
| 21 | 4 | PBKDF2 iteration count (uint32 LE) |
| 25 | 12 | AES-256-CTR nonce for the wrap |
| 37 | 32 | wrapped key ciphertext |
| 69 | 32 | HMAC-SHA256 tag over bytes `[0, 69)` |

**Why PBKDF2-HMAC-SHA256 over an OS keystore.** Windows DPAPI and Linux
`libsecret`/keyring were considered first, since the brief calls them out
explicitly. Both were rejected on portability/testability grounds specific
to this project: DPAPI is Windows-only and user/machine-bound, with no
Linux equivalent to exercise the same code path in this project's existing
6-way CI matrix (native Linux/Windows, ASan/UBSan, `qemu-aarch64`, and two
`qemu-x86_64` legs with different `-cpu` models); `libsecret` needs a
running D-Bus session and keyring daemon, which isn't reliably present in
a headless CI runner. A passphrase+KDF wrapping scheme has no such
dependency — it's exercised identically on every platform this project
already tests on. This is the same shape as
[age's scrypt recipient](https://c2sp.org/age@v1.1.0) and OpenSSH's
`bcrypt_pbkdf`-wrapped private keys, both cross-checked while designing
this.

**Why PBKDF2-HMAC-SHA256 over Argon2id/scrypt.** OWASP's
[Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
ranks Argon2id first, then scrypt, then bcrypt, and lists PBKDF2 last — "the
preferred algorithm when [FIPS-140 compliance is] required" — so this is
not the highest-security choice on the table. It was chosen anyway because
this project has zero external dependencies (confirmed: no `FetchContent`/
`find_package` anywhere in `CMakeLists.txt`) and hand-rolls its own
primitives (AES-256, CSPRNG) rather than vendoring a crypto library.
Argon2id and scrypt are memory-hard constructions — meaningfully more code
and attack surface to implement from scratch correctly than PBKDF2-HMAC-SHA256,
which reduces to a simple, well-analyzed HMAC feedback loop
([RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) §5.2) that's
easy to validate against known-answer tests. OWASP's own number for
PBKDF2-HMAC-SHA256 (600,000 iterations) is used as the default
(`kDefaultPbkdf2Iterations`), and NIST SP 800-132's floor (≥1000
iterations, ≥128-bit salt) is also met (this design uses a 128-bit salt).
This is a disclosed implementation-simplicity tradeoff, not a claim that
PBKDF2 is the strongest available option.

**Why encrypt-then-MAC.** This project's AES-256-CTR is unauthenticated by
design (see "Known limitations" below) — CTR ciphertext is bit-flip
malleable, so wrapping the raw key with CTR alone would let a
corrupted or tampered key file silently decrypt to 32 bytes of garbage
with no signal at all. Per the
[Encrypt-then-MAC](https://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)
principle, an HMAC-SHA256 tag is computed over the plaintext structure
(magic through wrapped ciphertext) and verified *before* decryption
(`load_from_file_encrypted` checks the tag first, throws
`AuthenticationError` on mismatch, and only calls `Aes256Ctr::decrypt` if it
matches) — this also avoids feeding attacker-controlled ciphertext into the
decrypt path at all when the tag doesn't verify.

**Key separation.** PBKDF2 derives 64 bytes from `(passphrase, salt,
iterations)`; the first 32 bytes become the AES-256-CTR wrapping subkey, the
next 32 the HMAC-SHA256 subkey. The two operations never share key
material, so a weakness in one primitive's use of its key can't be
leveraged against the other.

**Constant-time tag comparison.** `detail::constant_time_equal` XORs and
accumulates every byte rather than returning on the first mismatch,
specifically to avoid a timing side channel on MAC verification — a
`memcmp`/early-exit comparison here is a known, real vulnerability class
(non-constant-time MAC comparison enabling a timing oracle that leaks the
tag byte-by-byte, letting an attacker forge or brute-force a valid tag
without knowing the passphrase). No such helper previously existed in this
codebase; it was added specifically for this feature and is also usable
for other tag-verification needs in the future.

**Threat model.** This protects against: an attacker who obtains the key
file at rest without the passphrase (they get 101 bytes of salt + nonce +
ciphertext + tag, and PBKDF2's iteration count is the only thing between
them and a brute-force passphrase search); tampering with or corruption of
the key file (the HMAC tag catches any single-bit change, structural or
not); and rainbow-table-style precomputation across multiple key files
(each save generates a fresh random salt, so precomputed tables keyed on a
common passphrase-to-derived-key mapping don't transfer between files). It
explicitly does **not** protect against: a weak or guessable passphrase
(PBKDF2 slows brute force, it doesn't fix a bad passphrase); the passphrase
itself being captured via a keylogger, shoulder-surfing, or a compromised
input path; a GPU/ASIC-equipped attacker, against whom PBKDF2's lack of
memory-hardness makes it weaker than Argon2id/scrypt at the same wall-clock
cost (the tradeoff stated above); a live attacker with access to the
process while the key is resident in memory — this is the same caveat
bonus 3.6 (below) already states, and `save_to_file_encrypted`/
`load_from_file_encrypted` build on the same `SecretKey` type, so they
inherit its `mlock`/wipe-on-destruction protections for the derived
subkeys and intermediate buffers, but the underlying exposure-while-in-use
caveat still applies; and this is not hardware- or account-bound the way
DPAPI or a TPM-sealed key would be — anyone with the passphrase can decrypt
the file on any machine.

**Hardening against a malicious/corrupted file.** A second review pass on
this feature (after the first, which added the RFC/FIPS known-answer tests
above) found gaps and fixed them. First, `iterations == 0` was silently
accepted and collapses PBKDF2 to a single HMAC evaluation, defeating
iteration stretching entirely; both `save_to_file_encrypted` and
`load_from_file_encrypted` now reject it (`LimitError` on save,
`FormatError` on load). Second, `load_from_file_encrypted` reads `iterations`
straight from the file's own (untrusted, unauthenticated-until-verified)
header and must run PBKDF2 with it *before* the HMAC tag can be checked —
verifying the tag needs the MAC subkey, which only PBKDF2 produces. A
corrupted or deliberately hostile file could therefore claim an enormous
iteration count and force an effectively unbounded PBKDF2 computation before
authentication ever gets a chance to reject it. `load_from_file_encrypted`
now also rejects any iteration count above `kMaxPbkdf2Iterations`
(50,000,000 — roughly 80x the 600,000 default, chosen high enough to never
reject a legitimate file while still bounding worst-case load time to a
handful of seconds). Third — found via a follow-up look at the `age`
encryption tool's own postmortem on this exact class of bug
([FiloSottile/age#417](https://github.com/FiloSottile/age/issues/417),
concerning its scrypt recipient) — rejecting only `iterations == 0` wasn't
enough: a corrupted or hostile file could instead claim a small-but-nonzero
count (e.g. 1), which `load_from_file_encrypted` would accept and derive the
MAC subkey with negligible stretching. That's not a live exposure for this
project's own local-file usage, but it's the same shape of bug — a file's
own header controlling its KDF work factor — that let age's scrypt
recipient make an attacker's own passphrase guesses artificially cheap if
anything ever offers a decrypt-with-passphrase oracle over such files. Both
`save_to_file_encrypted` and `load_from_file_encrypted` now enforce a floor
of `kMinPbkdf2Iterations` (1000, matching NIST SP 800-132's PBKDF2 minimum,
which this section already cited but the code didn't previously enforce).
This is now stated as part of the threat model: loading an untrusted file
bounds the caller's exposure to a bad iteration count in either direction,
in addition to the HMAC tag eventually catching the tampering itself. The
PBKDF2-derived scratch buffers (`derived`, `mac_key_array`,
`decrypted_bytes`) are also now wrapped in a `detail::ScopedWipe` RAII guard
rather than relying solely on a manual `secure_wipe()` call before every
return — the manual calls remain for the "wipe as soon as no longer needed"
property in the normal path, but the RAII guard is a backstop that also
covers exception paths (e.g. a thrown `IoError`/`FormatError`/
`AuthenticationError` partway through), which the manual-only version did
not.

**A measured tradeoff, not a hidden one.** PBKDF2-HMAC-SHA256 at 600,000
iterations is deliberately slow — that's the point, it's what makes
brute-forcing the passphrase expensive. On this project's own hardware,
`save_to_file_encrypted()` at the default iteration count takes on the
order of ~1 second in an optimized build, and measurably longer (multiple
seconds) under ASan/UBSan or emulation, since this is a from-scratch,
non-vectorized, scalar SHA-256 implementation computing on the order of a
million HMAC-SHA256 calls per derivation. `iterations` is an explicit,
overridable parameter for callers (e.g. tests) who need a faster derivation
and can accept a smaller security margin; production callers should keep
the default.

This section's design decisions were informed by:

- **[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)**:
  the source for the 600,000-iteration PBKDF2-HMAC-SHA256 default, and for
  the explicit acknowledgment that OWASP ranks PBKDF2 below
  Argon2id/scrypt/bcrypt.
- **[NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)**: the
  ≥1000-iteration, ≥128-bit-salt floor this design meets.
- **[RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)**: PBKDF2's
  construction (§5.2), implemented directly against the spec.
- **[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) / FIPS 198-1**: HMAC's
  construction; **FIPS 180-4**: SHA-256's constants and compression
  function — both implemented from scratch, and checked against
  [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)'s HMAC-SHA256 test
  vectors and [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html)
  Appendix A's PBKDF2-HMAC-SHA256 test vectors in
  `tests/test_key_storage.cpp` (not just round-trip tests against itself —
  a save/load round trip calling the same primitive on both ends can't
  catch an internally self-consistent but wrong implementation; only
  comparison against an independent reference can).
- **[age's scrypt recipient](https://c2sp.org/age@v1.1.0)** and OpenSSH's
  `bcrypt_pbkdf`-wrapped keys: the reference shape for "passphrase + KDF +
  symmetric wrap + fresh salt per file" that this format follows.
- **[Encrypt-then-MAC](https://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)**:
  the rationale for authenticating the wrapped key rather than leaving it
  as bare unauthenticated CTR ciphertext.

### Key generation ergonomics (bonus 3.5)

`SecretKey`'s API is designed so a caller has to work to misuse it, rather
than relying on documentation to warn them off:

- **Named factories, no public default state.** `generate()` and
  `load_from_file()` are the only ways to obtain a `SecretKey`; the default
  constructor is private, so there's no way to end up holding a
  default-constructed, all-zero "key" that looks valid but isn't. Both
  factories are `[[nodiscard]]` — a stray `SecretKey::generate();` with the
  result thrown away is always a bug, and this turns it into a compiler
  warning instead of a silently-generated-and-destroyed key.
- **Move-only and `final`.** Copy is `= delete`d (no accidental duplication
  by value), and the class is marked `final` — it hand-manages a wipe/lock
  resource in its special members, and disallowing derivation closes off a
  category of lifetime/slicing misuse a subclass could otherwise introduce.
- **No public raw-byte accessor.** The class used to expose a public
  `bytes()` returning `const std::array<std::byte, 32>&`. That's a real
  footgun: any caller — not just the AES backends that actually need raw
  access for key expansion — could write `auto leaked = key.bytes();` (a
  silent copy into a plain local array that outlives the `SecretKey`,
  escaping wipe/`mlock` entirely) or `std::cout << (int)key.bytes()[0];`
  (trivial accidental logging). Neither `aes256_ctr.cpp` nor `main.cpp` ever
  called it — only the two backends' key-expansion code did. `bytes()` was
  removed and replaced with `aeslib::detail::key_bytes()`, a `friend` free
  function declared in `key.hpp` but reachable only from `.cpp` files that
  `#include "src/internal.hpp"` — i.e. the two AES backends and the test
  suite (which reaches it the same way it already reaches `ct_sbox`). An
  external caller linking against the public `include/aeslib/` headers has
  no way to read, copy, or print raw key bytes at all; the only sanctioned
  way to get key material out of a `SecretKey` is the explicit,
  deliberately-named `save_to_file()`.

This last point follows guidance from multiple independent sources:

- **[SEI CERT C++ Coding Standard](https://cmu-sei.github.io/secure-coding-standards/sei-cert-cpp-coding-standard/)**:
  Rule against returning references to a member less accessible than the
  member is meant to be — the public `bytes()` getter was exactly that
  anti-pattern.
- **["Designing the API for a cryptographic library: A misuse-resistant
  application programming interface"](https://www.researchgate.net/publication/262426179_Designing_the_API_for_a_cryptographic_library_A_misuse-resistant_application_programming_interface)**:
  The design principle behind NaCl's API (identified as the least
  misuse-prone cryptographic library in a comparative study across languages):
  raw key bytes shouldn't be accepted or returned by anything except the code
  that constructs/consumes the key type itself.
- **[Rust's `secrecy` crate](https://docs.rs/secrecy)**: `Secret<T>`/`ExposeSecret`
  trait applies the same idea in a different language — one explicit, narrow,
  auditable access path instead of an ordinary public getter every caller can
  reach.

All three independently converge on the same fix: kill the public raw-bytes
accessor.

### Minimizing key exposure in memory (bonus 3.6)

Four techniques are used together, addressing the raw key, its most
sensitive derivative, and the file-I/O path key bytes travel through —
informed by how libsodium's `sodium_mlock`/`sodium_memzero`, OpenSSL's
`OPENSSL_cleanse`, and Bitcoin Core's locked-memory allocator handle the
same problem (sources below):

- **Wipe on destruction/move.** `SecretKey::wipe()` zeroes the backing
  buffer via a `volatile` reference loop, not a plain `std::fill`/`= {}` —
  a non-`volatile` zero write immediately before the buffer goes out of
  scope is exactly the kind of "dead store" an optimizer is entitled to
  delete, since nothing else observably reads the memory again. `volatile`
  forces the write to actually happen. This is the same effect
  `explicit_bzero`/`memset_s`/`SecureZeroMemory` achieve by other means
  (`explicit_bzero` isn't used directly since it isn't in the C++17
  standard library and isn't universally available — glibc has had it since
  2.25, but not every libc/platform this library targets does); OpenSSL's
  own `OPENSSL_cleanse` uses a different compiler-barrier trick (a
  `volatile` *function pointer* to `memset`, called through indirectly) to
  the same end. All of these exist because a *non-volatile* zero-write
  right before deallocation is a dead store by the language's own rules,
  not a compiler bug — the volatile loop here is a standard, portable way
  to opt out of that rule for exactly the bytes that need it.
- **Swap and core-dump protection.** The constructor `mlock()`s (POSIX) or
  `VirtualLock()`s (Windows) the key's backing pages so they're pinned in
  RAM and excluded from swap/pagefile for as long as the `SecretKey` is
  alive; `wipe()` calls the matching `munlock()`/`VirtualUnlock()` right
  after zeroing, since that's exactly the point at which the memory stops
  holding a live key. On Linux specifically, `lock_memory()` additionally
  calls `madvise(MADV_DONTDUMP)` (and `unlock_memory()` calls the
  complementary `MADV_DODUMP`): `mlock()` says nothing about core dumps by
  itself — a page can be both locked in RAM *and* written into a
  `SIGSEGV`/`SIGABRT`-triggered core file, since those are separate kernel
  mechanisms. `MADV_DONTDUMP` is the Linux-specific opt-out for the second
  one; libsodium's `sodium_mlock` does the same pairing for the same
  reason. There's no BSD/macOS equivalent (no `MAP_NOCORE`-style flag for
  an already-mapped stack range), so this half is Linux-only — on
  macOS/BSD, a core dump taken while a `SecretKey` is alive can still
  contain it, which is consistent with the "inspecting a still-live
  process" carve-out below. The move constructor/assignment re-lock the
  (relocated) destination and unlock the vacated source, so a moved-from
  `SecretKey` never keeps its old storage pinned or dump-excluded. The
  return value of `mlock`/`madvise`/`VirtualLock` is deliberately ignored —
  `mlock` can fail without `CAP_IPC_LOCK` or a sufficient
  `RLIMIT_MEMLOCK` (the default in many containers), and this feature is
  defense-in-depth layered on top of the wipe/non-copy guarantees, not
  something key generation should hard-fail over on a host where the
  memlock limit happens to be tight. Verified directly: running the
  harness under `ulimit -l 0` still succeeds, and a Linux-only test
  (`key.generate_increases_locked_memory_on_linux`) reads
  `/proc/self/status`'s `VmLck` field to confirm the lock take effect when
  the platform allows it, without failing the suite when it doesn't (e.g.
  a tight `RLIMIT_MEMLOCK` in CI). **Windows caveat, stated rather than
  glossed over:** `VirtualLock` is a weaker guarantee than POSIX `mlock` —
  it pins pages into the process's *working set*, but Windows can still
  page them out once the process has no thread scheduled to run, which
  `mlock` does not do. A small-secret-specific alternative,
  `CryptProtectMemory` (DPAPI), encrypts the buffer in place with a
  kernel-held, per-boot key instead of merely pinning it, which also
  keeps it out of user-mode crash dumps — a stronger property than this
  library's plain-`VirtualLock` approach gives on Windows. It isn't used
  here to keep the locking code path uniform across platforms (one
  pin/unpin API rather than a Windows-only encrypt/decrypt-around-every-use
  scheme), but it's the documented next step if Windows-specific hardening
  mattered more than portability for a given deployment.
- **Avoiding unnecessary copies in the file-I/O path.**
  `save_to_file()`/`load_from_file()` write/read key bytes through raw
  `write(2)`/`read(2)` (POSIX) or `WriteFile`/`ReadFile` (Windows) directly
  against `bytes_`, not through `std::ofstream`/`std::ifstream`. An
  iostream sink/source copies through its own internal `streambuf` on the
  way to/from the OS — an incidental, unwiped extra copy of key material
  living in libstdc++/MSVC-internal buffer memory that outlives the call
  and that neither `wipe()` nor `mlock()` ever touches. This is exactly
  the "avoiding unnecessary copies of key material" technique the brief
  calls out, applied to the one place in this codebase key bytes cross an
  I/O boundary.
- **Wiping the derived key schedule, not just the key.** Both AES
  backends expand the raw key into a full round-key schedule
  (`expand_key`/`expand_key_ni`) — 240 bytes of `Word`s in the software
  path, 15 `__m128i` round keys in the AES-NI path — and this expansion
  runs once *per 16-byte block*, since CTR mode calls the block cipher
  once per keystream block. The schedule is a direct, reversible function
  of the raw key and is exactly as sensitive, and because it's
  recomputed continuously during encryption/decryption rather than once
  per key lifetime, it spends far more aggregate time sitting unwiped in
  stack memory than the key itself ever does — a gap a wipe-only-the-key
  approach would miss entirely. Both
  `aes256_encrypt_block_soft`/`aes256_encrypt_block_ni` zero their local
  `schedule` array (same `volatile`-write technique as `SecretKey::wipe()`,
  applied byte-wise since `Word`/`__m128i` aren't safely `volatile`-loopable
  element-wise) immediately after the last round that consumes it. The
  schedule isn't `mlock`ed — it's stack-resident and short-lived enough
  (one block's worth of encryption) that the cost/benefit favors just
  wiping it promptly, unlike the key, which can live for the process's
  entire runtime.

**Threat model.** This protects against: key or schedule bytes surviving,
readable, past their logical lifetime in a stack/heap dump taken *after*
the owning object/stack frame is gone; key material being written to
swap/the pagefile while a `SecretKey` is alive; key material appearing in
a Linux core dump taken while a `SecretKey` is alive; incidental copies of
key bytes left behind in iostream buffer memory; and accidental
duplication via the API surface. It explicitly does **not** protect
against: inspecting a still-*live* process (an attached debugger, `ptrace`,
or a core dump taken *while* a `SecretKey` or a round-key schedule is still
in scope — the raw bytes are, by necessity, resident as ordinary
unencrypted memory while actually being used for encryption; avoiding that
entirely is the "far end of the spectrum" the brief calls out — e.g.
hardware enclaves, an HSM, or never materializing the key outside a
keystore process — and isn't attempted here); an attacker with root/kernel
privileges; `mlock`/`VirtualLock`/`madvise` failing silently on a host with
a tight memlock limit (an accepted, stated tradeoff, not a bug); a cold-boot
attack — DRAM (and SRAM) retain their contents for seconds to minutes after
power loss, so an attacker with physical access can reboot into a minimal
OS and dump pre-boot RAM contents wholesale, recovering a still-resident
key regardless of `mlock`/wipe-on-destruction (those only govern *this
process's* logical key lifetime, not what's electrically still in the DIMM
after the machine loses power); whole-system hibernate-to-disk on
OSes/configurations where that can bypass `mlock`; or side channels beyond
what the constant-time software S-box (above) already addresses. Safer key
*storage* (OS keystore, KDF-wrapped keys) is a separate bonus objective
(3.4), covered above.

This section's design decisions were informed by:

- **[Libsodium: Secure memory](https://libsodium.gitbook.io/doc/memory_management)**:
  `sodium_mlock`/`sodium_munlock` pairing `mlock`/`munlock` with
  `madvise(MADV_DONTDUMP)`/`MADV_DODUMP` on Linux, and `sodium_memzero`'s
  role as a compiler-optimization-proof zeroing primitive — the direct
  model for this library's `lock_memory()`/`unlock_memory()`/`wipe()`.
- **[OpenSSL `crypto/mem_clr.c`](https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c)**:
  `OPENSSL_cleanse`'s volatile-function-pointer-to-`memset` technique, an
  alternative compiler-barrier approach to the volatile-loop one used here,
  useful for confirming the *reason* a volatile-based zero survives
  optimization (a language-level dead-store rule, not an implementation
  quirk) rather than just copying the pattern.
- **[Bitcoin Core PR #15600 — "use madvise to avoid including sensitive
  information in core dumps"](https://github.com/bitcoin/bitcoin/pull/15600)**:
  a concrete, reviewed example of the same `mlock` + `MADV_DONTDUMP` gap
  this library closes, in a production codebase with the same "keys must
  not linger in memory" concern.
- **["VirtualLock only locks your memory into the working set" — The Old
  New Thing](https://devblogs.microsoft.com/oldnewthing/20071106-00/?p=24573)**:
  the source for the Windows caveat above — `VirtualLock`'s guarantee is
  weaker than POSIX `mlock`'s, which this library states rather than
  implying parity between the two platform calls.
- **[MSDN: `CryptProtectMemory`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)**:
  the Windows-native alternative to plain `VirtualLock` for small secrets —
  documented above as the road not taken, and why.
- **["Lest We Remember: Cold-Boot Attacks on Encryption Keys" (Halderman et
  al.)](https://cacm.acm.org/research/lest-we-remember/)**: the source for
  the cold-boot/DRAM-remanence entry in the threat model above — the
  canonical demonstration that RAM-resident keys survive a power cycle long
  enough to be extracted, which is precisely the class of attack no
  process-level `mlock`/wipe scheme (this one included) can defend against.

## Additional AES modes: AES-128 + AES-GCM (bonus)

This bonus adds two things: AES-128 key support (alongside the existing
AES-256), and AES-GCM, an authenticated mode, alongside the existing
unauthenticated `Aes256Ctr`. CBC mode was deliberately **not** implemented —
see below for why.

**Why a `KeySize` discriminant on `SecretKey`, not a template.** The
obvious alternative was `template <KeySize> class SecretKey` (or a
`SecretKey128`/`SecretKey256` pair of types). Both were rejected: `SecretKey`
is the one type touched by every hardened bonus in this codebase (3.4's
encrypted storage, 3.5's misuse-resistant API, 3.6's memory protection) —
templating it would force either duplicating all of that logic per
instantiation or threading a template parameter through every function that
currently takes `const SecretKey&`, for a blast radius far out of proportion
to "the key is sometimes 16 bytes instead of 32." A runtime `size_` field
keeps every existing call site (`Aes256Ctr`, both backends' key-expansion
code, `save_to_file`/`load_from_file`) touched by nothing but the two
addition points that actually need to branch on size: the block-cipher
dispatch (`aes_gcm.cpp`'s `encrypt_block`) and the file-format size marker.
`bytes_` itself stays a fixed 32-byte array rather than becoming
variable-length — an AES-128 key only reads/saves its first 16 bytes, and
the unused 16 are still genuine CSPRNG output, `mlock`ed and wiped exactly
like the rest, which is a simpler invariant to maintain than a
sometimes-16/sometimes-32-byte buffer would be.

**Software backend: one template, not a second hand-written cipher.**
`src/aes_core_soft.cpp`'s `expand_key`/`add_round_key`/`wipe_schedule`/the
block-encrypt body were already loop-driven over `Nk`/`Nr` rather than
unrolled, so parameterizing them as `template <int Nk, int Nr>` functions
was the low-risk path: `aes256_encrypt_block_soft` becomes a one-line call
to `aes_encrypt_block_soft<8, 14>`, provably behaviorally identical to the
pre-refactor code (confirmed by the pre-existing FIPS-197 Appendix C.3 KAT
continuing to pass unchanged), and `aes128_encrypt_block_soft` is
`aes_encrypt_block_soft<4, 10>`. The one schedule-generation subtlety
(FIPS-197 5.2's extra `SubWord` step for `Nk > 6`) is written as a generic
`i % Nk == 4` branch that's simply never true when `Nk == 4`, so AES-128's
simpler 10-round schedule falls out of the same code path with no separate
`if constexpr` or specialization needed.

**AES-NI backend: a wholly separate routine, not shared code.** The
existing AES-256 key expansion (`expand_key_ni` in `aes_core_ni.cpp`) is
hand-unrolled via macros built around the Nk=8 schedule's two-word-per-step
`temp1`/`temp3` structure, driven by the fact that
`_mm_aeskeygenassist_si128`'s round-constant argument must be a
compile-time immediate (so it can't be looped over an array at runtime).
AES-128's schedule advances one word per step, not two — a structurally
different shape, not a smaller instance of the same one — so rather than
contort the existing macros to also handle a single-chain schedule, AES-128
gets its own `expand_key128_ni`/`aes128_encrypt_block_ni`, following the
standard `KEY_128_ASSIST` pattern from Intel's "Advanced Encryption
Standard Instructions (AES-NI)" white paper (Gueron). The existing AES-256
code is untouched — zero regression risk to code that's already been through
two independent review passes (see bonus 3.4's log above).

**GCM design.** `AesGcm::encrypt()`/`decrypt()` (`include/aeslib/aes_gcm.hpp`,
`src/aes_gcm.cpp`) follow NIST SP 800-38D: for a 96-bit nonce, `J0 = nonce
|| 0x00000001` (the same nonce||counter construction `Aes256Ctr` already
uses, see the "Nonce/IV strategy" section above, which now also covers why
nonce reuse is strictly worse under GCM than CTR), keystream blocks are
generated starting at counter 2 (counter 1/`J0` is reserved for encrypting
the tag), and the authentication tag is `E(K, J0) XOR GHASH_H(AAD,
ciphertext)`. This reserves one counter value `J0` uses, so this
construction's per-invocation limit is 2^32-2 blocks, one less than CTR's
2^32. `decrypt()` recomputes the expected tag and compares it against the
stored one via the existing `detail::constant_time_equal` (already used by
bonus 3.4's HMAC verification) *before* decrypting anything — the same
verify-then-decrypt discipline as `load_from_file_encrypted`, so a
tampered ciphertext or tag is rejected without ever touching the (still
attacker-influenced) ciphertext bytes with the decrypt transform.

**GHASH implementation and constant-time design.** `src/ghash.cpp`
implements GF(2^128) multiplication (`gf128_mul`, NIST SP 800-38D
Algorithm 1) as a 128-iteration bit-serial shift-and-conditionally-XOR
loop, using a bitmask rather than an `if` to fold in each bit of the
secret operand — the same discipline `gmul`/`gf256_inv` already apply to
AES's S-box in `aes_core_soft.cpp`, extended here because both `gf128_mul`
operands are secret-derived (the running GHASH accumulator, and the
GHASH subkey `H = E(K, 0^128)`). `ghash()` then folds zero-padded 16-byte
blocks of AAD, then ciphertext, then a final "length block" (the
bit-lengths of AAD and ciphertext, big-endian) into an accumulator via
repeated `gf128_mul` calls, per SP 800-38D §6.4. No PCLMULQDQ
acceleration is used — GHASH stays portable, branch-free C++ like the rest
of the non-AES-NI code, so it needs no `set_source_files_properties`
scoping in `CMakeLists.txt` the way `aes_core_ni.cpp`'s `-maes` flag does.

**Container format.** See the "On-disk container format" section above for
the `.aesg` wire-format table (distinct `"AESG"` magic from `Aes256Ctr`'s
`"AESC"`, so the two can't be confused) and the key-file format's version-2
size marker.

**Scope limitations, stated explicitly:**

- **CBC mode was not implemented.** GCM was chosen instead because it's
  forward-cipher-only — the existing AES-NI/software backends only ever
  implement AES *encryption* (CTR never needed decryption, so
  `InvSubBytes`/`InvMixColumns`/etc. simply don't exist in this codebase),
  and GCM's keystream generation is exactly that same forward-only
  operation. CBC *decryption* would require implementing the full AES
  inverse cipher in both backends — real new work nothing else in this
  library needs — for a mode that's also a strict security downgrade from
  GCM (confidentiality only, no integrity/authentication, and CBC padding
  oracles are a well-documented real-world attack class GCM avoids
  entirely by not padding at all). Given a choice between implementing one
  new mode's forward-only cipher work (GCM) versus another mode's
  forward-and-inverse cipher work for a weaker security property (CBC),
  GCM was the better use of the same engineering effort.
- **`Aes256Ctr` remains AES-256-only.** `SecretKey::size_bytes()` makes
  AES-128 available to it in principle, but `Aes256Ctr`'s name, its
  existing test/reference-vector suite, and its role as this library's
  original (still supported) unauthenticated mode were left untouched;
  `AesGcm` is the one construction that dispatches on key size.
- **`save_to_file_encrypted`/`load_from_file_encrypted` (bonus 3.4) remain
  AES-256-only.** The wrapped-key format wraps the full `kKeySizeBytes` (32)
  of `bytes_` unconditionally; for an AES-128 key that would silently
  include the 16 unused-but-random bytes past its logical end as if they
  were key material, and `load_from_file_encrypted` always reconstructs a
  `KeySize::Aes256` key on the way back out — so an AES-128 key's round
  trip through that format would silently fabricate 16 bytes of "key" that
  were never part of the original. `save_to_file_encrypted` now guards
  against this explicitly (`throw LimitError` for a non-AES-256 key)
  rather than leaving it as a silent correctness bug. Extending the
  wrapped-key format itself to support AES-128 (its own size marker, and a
  variable-length wrapped-key field instead of the current fixed 32 bytes)
  is future work, not attempted in this pass.

This section's design decisions were informed by:

- **[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)**: the
  GCM specification itself — `J0` construction, the GHASH function over
  GF(2^128), tag computation/verification, and the CAVP validation-vector
  program that motivated cross-checking hardcoded vectors against two
  independent implementations (Python's `cryptography` and
  `pycryptodome`) rather than trusting one source, mirroring
  `tests/test_reference_vectors.cpp`'s existing methodology.
- **Intel's "Advanced Encryption Standard Instructions (AES-NI)" white
  paper (Gueron)**: the standard `AESKEYGENASSIST`-based AES-128
  key-expansion routine (`KEY_128_ASSIST`), the basis for
  `expand_key128_ni`.
- **Joux's "forbidden attack" on GCM nonce reuse**, and the 2016
  "Nonce-Disrespecting Adversaries" survey: the source for the nonce-reuse
  severity comparison in the "Nonce/IV strategy" section above — real
  HTTPS servers were found reusing GCM nonces in practice, not merely a
  theoretical concern.

## Randomness

Keys and nonces are generated via the OS's native CSPRNG (`BCryptGenRandom`
on Windows, `getrandom(2)` on Linux, `arc4random_buf` elsewhere) — never
`rand()`, `std::mt19937`, or any other non-cryptographic PRNG.

## Error handling

Four exception types cover this library's failure modes: `aeslib::IoError`
(filesystem/OS failures), `aeslib::FormatError` (malformed container/key
files), `aeslib::LimitError` (a request exceeds a format-imposed size limit,
or asks for an operation this library deliberately doesn't support — the
CTR/GCM block-counter bounds, see the nonce/IV strategy section above, and
`save_to_file_encrypted` rejecting a non-AES-256 key, see "Additional AES
modes" above), and `aeslib::AuthenticationError` (a passphrase-protected key
file's HMAC tag doesn't verify, or a GCM container's authentication tag
doesn't verify — wrong passphrase/key/nonce/AAD, or a tampered/corrupted
file; kept distinct from `FormatError` so callers can tell "ask for the
passphrase again" / "this data isn't authentic" apart from "file is
unreadable"). Nothing in the public API uses output-parameter error codes.

## Known limitations / threat model

Stated plainly, rather than left for a reviewer to infer:

- **No authentication.** CTR mode as implemented here provides
  confidentiality only, not integrity. Ciphertext is malleable: flipping a
  bit in the ciphertext flips the corresponding bit in the decrypted
  plaintext, undetected, since there is no MAC or authentication tag
  anywhere in the container format. A caller needing tamper-evidence needs
  to layer one on (e.g. HMAC over the container, or a future AEAD-mode
  version — the container format's version byte exists partly to allow
  that without breaking old readers, see "On-disk container format" above).
  This is a scope boundary, not an oversight: the challenge brief specifies
  CTR mode, which is inherently unauthenticated.
- **Nonce birthday bound.** Covered above — random 96-bit nonces mean
  collision risk becomes non-negligible only after ~2^48 encryptions under
  one key, which is far beyond this library's expected single-key volume,
  but is a real bound rather than "impossible."
- **Software-path cache timing** is addressed, not just documented: see
  "Constant-time software S-box" above.

## Test/production isolation

Because this submission also ships a test suite (`tests/`) and a
production-only-visible internal header (`src/internal.hpp`), it's worth
stating explicitly what was verified about the boundary between them, so a
reviewer doesn't have to re-derive it:

- The `AESLIB_EXPECTED_BACKEND` environment variable used by CI to assert
  which dispatch path ran (see "How the dispatch is verified" above) is read
  in exactly one place in the entire codebase: `tests/test_backend.cpp`. No
  `getenv`/`std::getenv` call exists anywhere under `src/` or `include/` —
  production dispatch logic (`cpu::has_hw_aes()` in `src/cpu_detect.cpp`,
  `active_backend()` in `include/aeslib/backend.hpp`) is driven purely by
  the hardware-capability check itself and cannot be steered by that or any
  other environment variable.
- `src/internal.hpp` (the `Block`/`aes256_encrypt_block_*`/`cpu::has_hw_aes`/
  `rng::fill_random`/`ct_sbox`/`validate_block_count` declarations tests need
  to reach internals directly) is included only by production `.cpp` files
  under `src/` — never by anything under `include/aeslib/`. A consumer
  linking `aeslib` through its public include directory never sees it.
- The `aeslib` CMake target lists only production sources; `aeslib_tests`
  is a separate executable, and its `${CMAKE_SOURCE_DIR}` include path
  (needed to reach `internal.hpp`) is scoped `PRIVATE` to that test target
  only, never propagated to `aeslib` or anything linking it.
- Setting `-DAESLIB_BUILD_TESTS=OFF` removes `add_subdirectory(tests)` from
  the build entirely — the `aeslib` library target is unaffected either way,
  since it never referenced test code, test include paths, or test compile
  definitions in the first place.
- There is no `install()`/`export()` rule in this project at all, so nothing
  currently packages test code, `internal.hpp`, or anything else for
  distribution.

## ARM AArch64 Crypto Extensions (bonus 3.2), and the next architecture after that

The dispatch model deliberately isolates *all* architecture-specific code
behind one interface: functions with an identical signature
(`Block aesNNN_encrypt_block_*(const SecretKey&, const Block&)`) plus a
one-function CPU-capability check. This section originally argued that
adding ARM support would be straightforward given that isolation; it now
describes what was actually built, plus a third architecture (RISC-V) that
the same isolation would make similarly straightforward to add next.

**The `_hw` dispatch wrapper.** Before this bonus, `aes256_ctr.cpp`/
`aes_gcm.cpp` called `detail::aesNNN_encrypt_block_ni(...)` by name whenever
`active_backend() == Backend::Hardware`. Adding a second hardware backend
meant there were now two possible "real" implementations that are never both
real in the same build — rather than sprinkling `#if`s across both mode
files, `src/aes_core_hw.cpp` is the one new file that owns that choice,
exposing `aesNNN_encrypt_block_hw()` wrappers implemented purely as
`#if`/`#elif` on the target architecture (x86 → `_ni`, arm64 → `_arm`, else →
throws). `aes256_ctr.cpp` and `aes_gcm.cpp` each needed a **one-line**
change — `_ni` → `_hw` in their local `encrypt_block()` helper — confirming
the "no changes anywhere else in the library" claim this section originally
made.

**Runtime detection, per OS.** `cpu::has_hw_aes()` (`src/cpu_detect.cpp`)
gained three arm64 branches alongside the existing x86 CPUID one, since
"does this CPU support the AArch64 Crypto Extensions" has no single
cross-platform answer:

- Linux: `getauxval(AT_HWCAP) & HWCAP_AES`.
- macOS (Apple Silicon): `sysctlbyname("hw.optional.arm.FEAT_AES", ...)`.
- Windows on ARM64: `IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)`.

Each is read once and memoized, exactly like the x86 CPUID check. An arm64
target under an unrecognized OS falls back to `false` (software path) rather
than guessing — a documented, safe limitation rather than a silent
correctness risk.

**No key-expansion instruction, unlike AES-NI.** x86's AES-NI has
`_mm_aeskeygenassist_si128`, a dedicated key-schedule-assist instruction,
which is why `aes_core_ni.cpp` has its own hand-written schedule routine
separate from the software backend's. ARM's Crypto Extensions have no
equivalent — `AESE`/`AESMC` only accelerate the 16-round block *transform*,
not the schedule — so real-world implementations (mbedTLS's `aesce.c`,
Botan's `aes_armv8.cpp`) compute the round-key schedule in portable code.
Rather than writing a third copy of FIPS-197 §5.2, the existing
`expand_key<Nk,Nr>` template was extracted from `aes_core_soft.cpp`'s
anonymous namespace into `src/aes_key_schedule.hpp`, a shared internal
header both `aes_core_soft.cpp` and `aes_core_arm.cpp` now include.
`aes_core_arm.cpp` calls it, packs each 16-byte round key into a
`uint8x16_t`, and runs the standard ARMv8 round loop:

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
the previous one. This reproduces standard FIPS-197 encryption because
SubBytes and ShiftRows commute: ShiftRows only permutes byte *positions*,
and SubBytes substitutes every byte identically regardless of position, so
folding round *r*'s trailing AddRoundKey into round *r+1*'s leading
SubBytes/ShiftRows is equivalent to doing them in the textbook order. The
round-key schedule is wiped the same volatile-write way every other backend
wipes its derived key material (see "Minimizing key exposure in memory"),
both as the `Word` array (`aes_key_schedule.hpp`'s shared `wipe_schedule`)
and as the packed `uint8x16_t` copy `aes_core_arm.cpp` builds from it.

**Build isolation.** Same rationale as `-maes` for `aes_core_ni.cpp`:
`aes_core_arm.cpp` is the *only* file compiled with `-march=armv8-a+crypto`
on GCC/Clang (see `CMakeLists.txt`'s new `AESLIB_TARGET_IS_ARM64` branch), so
the compiler never emits an AArch64 Crypto Extensions instruction anywhere
else in the binary. MSVC targeting ARM64 needs no equivalent flag — its
`<arm_neon.h>` exposes the crypto intrinsics unconditionally when targeting
ARM64, since Windows' ARM64 baseline always presumes NEON even though the
crypto extensions themselves remain an optional hardware feature checked at
runtime via `IsProcessorFeaturePresent` as above.

**Test reuse, not new test code.** `tests/test_aes_core.cpp`'s existing
hardware-path KAT and cross-check tests (`hardware_matches_fips197_kat_when_available`,
`backends_agree_on_random_blocks`, and their AES-128 equivalents) called
`aesNNN_encrypt_block_ni(...)` by name — on an arm64 build that would hit
`aes_core_ni.cpp`'s throwing stub rather than testing anything real. Changing
those four tests to call `aesNNN_encrypt_block_hw(...)` instead (the same
one-line substitution the production code got) makes them exercise whichever
hardware backend the build actually targets, with zero new arch-specific
test code. A new `expand_key_matches_fips197_appendix_a3` test checks the
now-shared schedule template directly against FIPS-197 Appendix A.3's
published 60-word AES-256 expansion, localizing a schedule bug independent
of round-transform correctness now that the schedule is shared by two
backends instead of duplicated once.

**The next architecture: RISC-V.** RISC-V has two relevant AES extension
families — `Zkne`/`Zknd` (scalar AES encrypt/decrypt round instructions,
under the `Zkn` umbrella) and `Zvkned` (vector AES, operating on 128-bit
element groups). Runtime detection on Linux goes through the `riscv_hwprobe()`
syscall rather than `getauxval(AT_HWCAP)`, since HWCAP only covers the base
ISA letters, not sub-extensions like these. Adding it would mean exactly the
three touch points ARM needed: one more `aes_core_riscv.cpp` implementing
`aesNNN_encrypt_block_riscv()`, one more `#elif` in `aes_core_hw.cpp`, and
one more branch in `cpu_detect.cpp`'s `has_hw_aes()` — no changes to
`aes256_ctr.cpp`, `aes_gcm.cpp`, or anything under `include/`. Whether
RISC-V's scalar AES instructions have a dedicated key-schedule-assist
instruction (the way AES-NI does, but ARM's Crypto Extensions don't) would
need checking against the ISA spec before implementation — if not, the same
shared `aes_key_schedule.hpp` this bonus introduced would serve a third
backend, not just two.
