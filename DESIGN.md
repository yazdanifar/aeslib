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
  aes_core_soft.cpp      portable AES-256 forward cipher (FIPS-197), no
                         intrinsics, used as the fallback
  aes_core_ni.cpp        AES-256 forward cipher using AES-NI intrinsics,
                         used when the CPU supports it
  cpu_detect.cpp          runtime CPUID check
  csprng.cpp              OS CSPRNG wrapper
  key.cpp, container.cpp  key/container (de)serialization and file I/O
  internal.hpp             shared declarations, not part of the public API
main.cpp                end-to-end harness (see README.md)
```

## Hardware/software dispatch

`aeslib::active_backend()` runs a CPUID check (`CPUID.1:ECX.AESNI`, bit 25)
the first time it's called and memoizes the result in a function-local
static — so the decision is made once, at runtime, on whatever machine the
binary happens to be running on. It is never baked in via `#ifdef __AES__`
or `-march=native`; the same compiled binary takes the hardware path on an
AES-NI-capable host and the software path on one without, which is what lets
one binary be correct on both. `Aes256Ctr` calls `active_backend()`
internally to pick which block-encrypt function to call; callers of the
public API never see this decision, but it's exposed as a free function so
tests/diagnostics can observe (and the `main.cpp` harness prints) which path
actually ran.

The AES-NI code lives in its own translation unit (`aes_core_ni.cpp`) and is
the *only* file compiled with `-maes` on GCC/Clang (see `CMakeLists.txt`);
every other file — including the CTR driver that calls into it — stays
free of any architecture-specific instruction set flags. That's what makes
it safe to ship as one portable binary: the compiler never emits an AES-NI
instruction outside that one file, and that file is only ever *called* after
`cpu::has_aes_ni()` has confirmed the instructions are safe to execute.

Because CTR mode only ever needs the forward AES transform (see below),
both backends implement encryption only — there is no AES decryption
routine anywhere in this codebase.

### How the dispatch is verified

2.2 requires that the *same binary* be correct on a machine with AES-NI and
one without. This is now verified on every push by `.github/workflows/ci.yml`
rather than resting on a one-off manual session:

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
3. `qemu-aarch64` cross-compiles for a genuinely different architecture and
   runs it under `qemu-aarch64-static`, confirming the non-x86 branch of
   `cpu_detect.cpp` (`AESLIB_X86` never defined) correctly reports no
   hardware path and the software fallback is used.

Before writing this workflow, the core premise — that `qemu-x86_64 -cpu
<model>` actually controls what a guest binary's `CPUID` instruction
reports, rather than passing through the host's real capabilities — was
verified directly against GitHub's runners: probing with `-cpu Westmere`,
`-cpu Nehalem`, `-cpu max`, and `-cpu max,-aes` produced AES-NI
`yes`/`yes`/`yes`/`no` respectively, exactly as expected.

**Limitation worth stating plainly:** QEMU's TCG will generally still
*execute* an `aesenc` instruction even when the CPUID feature bit is masked
off — real silicon would `SIGILL`. So `qemu-aes-off` proves that (a) CPUID
detection correctly reports AES-NI as absent under that model, and (b) the
software path it falls back to is byte-correct — it does not prove that
dispatch would crash safely-versus-silently-corrupt if the hardware branch
were ever taken on real AES-NI-less hardware by mistake. That gap is closed
by 1 and 2 above only insofar as the dispatch logic itself (a single `if` in
`cpu_detect.cpp`) is simple enough to read completely; it is not closed by
execution.

A standalone known-answer test (FIPS-197 Appendix C.3, AES-256) is also run
directly against `aes256_encrypt_block_ni()` and `aes256_encrypt_block_soft()`
in `tests/test_aes_core.cpp`, confirming both produce the exact published
ciphertext block for the same key/plaintext — i.e. the two backends don't
just each "work", they agree with each other and with the published test
vector, on every CI run.

### Constant-time software S-box

A textbook software AES implementation typically substitutes bytes via
`kSBox[secret_byte]` — a lookup table indexed by key- and state-dependent
data. That's a classical cache-timing side channel (Bernstein-style): which
cache line the lookup touches depends on the secret byte, and that's
observable by another process on the same core. The AES-NI backend never has
this problem (`aesenc` is constant-time by construction), but the software
fallback used to have it, silently, on any host without AES-NI.

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

Key file: `version (1 byte)` + `32` raw key bytes, written with `0600`
permissions on POSIX.

Both formats carry an explicit version byte specifically so a future format
change (e.g. switching to an AEAD mode and adding an authentication tag, or
a different nonce size) can be introduced without breaking the ability to
read files written by an older version of the library — a reader can
branch on the version byte before interpreting the rest of the layout.

## Key handling

`SecretKey` is move-only — copying is disabled at the type level, so a key
can't be accidentally duplicated by value — and every consumer in this
codebase (`aes256_ctr.cpp`, both AES backends) takes it by `const&`, so no
incidental copies of the raw key exist anywhere in the library.

### Minimizing key exposure in memory (bonus 3.6)

Three techniques are used together, addressing both the raw key and its
most sensitive derivative:

- **Wipe on destruction/move.** `SecretKey::wipe()` zeroes the backing
  buffer via a `volatile` reference loop, not a plain `std::fill`/`= {}` —
  a non-`volatile` zero write immediately before the buffer goes out of
  scope is exactly the kind of "dead store" an optimizer is entitled to
  delete, since nothing else observably reads the memory again. `volatile`
  forces the write to actually happen.
- **Swap protection.** The constructor `mlock()`s (POSIX) or
  `VirtualLock()`s (Windows) the key's backing pages so they're pinned in
  RAM and excluded from swap/pagefile for as long as the `SecretKey` is
  alive; `wipe()` calls the matching `munlock()`/`VirtualUnlock()` right
  after zeroing, since that's exactly the point at which the memory stops
  holding a live key. The move constructor/assignment re-lock the
  (relocated) destination and unlock the vacated source, so a moved-from
  `SecretKey` never keeps its old storage pinned. The return value of
  `mlock`/`VirtualLock` is deliberately ignored — `mlock` can fail without
  `CAP_IPC_LOCK` or a sufficient `RLIMIT_MEMLOCK` (the default in many
  containers), and this feature is defense-in-depth layered on top of the
  wipe/non-copy guarantees, not something key generation should hard-fail
  over on a host where the memlock limit happens to be tight. Verified
  directly: running the harness under `ulimit -l 0` still succeeds.
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
  element-wise) immediately after the last round that consumes it.

**Threat model.** This protects against: key or schedule bytes surviving,
readable, past their logical lifetime in a stack/heap dump taken *after*
the owning object/stack frame is gone; key material being written to
swap/the pagefile while a `SecretKey` is alive; and accidental duplication
via the API surface. It explicitly does **not** protect against: inspecting
a still-*live* process (an attached debugger, `ptrace`, or a core dump
taken *while* a `SecretKey` or a round-key schedule is still in scope — the
raw bytes are, by necessity, resident as ordinary unencrypted memory while
actually being used for encryption; avoiding that entirely is the "far end
of the spectrum" the brief calls out — e.g. hardware enclaves, an HSM, or
never materializing the key outside a keystore process — and isn't
attempted here); an attacker with root/kernel privileges; `mlock`/
`VirtualLock` failing silently on a host with a tight memlock limit (an
accepted, stated tradeoff, not a bug); whole-system hibernate-to-disk on
OSes/configurations where that can bypass `mlock`; or side channels beyond
what the constant-time software S-box (above) already addresses. Safer key
*storage* (OS keystore, KDF-wrapped keys) is a separate, optional bonus
objective (3.4) this submission doesn't attempt.

## Randomness

Keys and nonces are generated via the OS's native CSPRNG (`BCryptGenRandom`
on Windows, `getrandom(2)` on Linux, `arc4random_buf` elsewhere) — never
`rand()`, `std::mt19937`, or any other non-cryptographic PRNG.

## Error handling

Three exception types cover this library's failure modes: `aeslib::IoError`
(filesystem/OS failures), `aeslib::FormatError` (malformed container/key
files), and `aeslib::LimitError` (a request exceeds a format-imposed size
limit — currently just the CTR block-counter bound, see the nonce/IV
strategy section above). Nothing in the public API uses output-parameter
error codes.

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
  production dispatch logic (`cpu::has_aes_ni()` in `src/cpu_detect.cpp`,
  `active_backend()` in `include/aeslib/backend.hpp`) is driven purely by
  the CPUID check itself and cannot be steered by that or any other
  environment variable.
- `src/internal.hpp` (the `Block`/`aes256_encrypt_block_*`/`cpu::has_aes_ni`/
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

## Third architecture (not implemented, but why it'd be straightforward)

The dispatch model deliberately isolates *all* architecture-specific code
behind one interface: two functions with an identical signature
(`Block aes256_encrypt_block_*(const SecretKey&, const Block&)`) plus a
one-function CPU-capability check. Adding ARM AArch64 Crypto Extensions
support (or a third architecture) would mean adding one more
`aes_core_*.cpp` file implementing that same function signature with the
target's intrinsics, extending `cpu_detect.cpp`'s capability check for that
architecture, and adding one more arm to `active_backend()`'s dispatch — no
changes anywhere else in the library, since `Aes256Ctr` only ever calls
through the shared function signature and never branches on architecture
itself.
