#pragma once

// Internal-only declarations shared between the library's .cpp files. Not
// part of the public API in include/aeslib/.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "aeslib/key.hpp"

namespace aeslib::detail {

inline constexpr std::size_t kBlockSizeBytes = 16;
using Block = std::array<std::byte, kBlockSizeBytes>;

// Software AES forward cipher (encryption direction only — CTR/GCM never
// need AES decryption, see aes256_ctr.hpp/aes_gcm.hpp). Pure, portable C++.
Block aes256_encrypt_block_soft(const SecretKey& key, const Block& block);
Block aes128_encrypt_block_soft(const SecretKey& key, const Block& block);

// The software backend's constant-time GF(2^8)-inversion S-box (see
// src/aes_core_soft.cpp). Exposed here purely so tests can check it against
// the canonical AES S-box table for all 256 inputs; not part of the public
// API.
std::uint8_t ct_sbox(std::uint8_t x);

// Same operations, implemented with AES-NI intrinsics (amd64). Only ever
// called after cpu::has_hw_aes() has been confirmed true; must not be called
// otherwise since the process may fault executing an unsupported instruction.
Block aes256_encrypt_block_ni(const SecretKey& key, const Block& block);
Block aes128_encrypt_block_ni(const SecretKey& key, const Block& block);

// Same operations, implemented with AArch64 Crypto Extensions intrinsics
// (AESE/AESMC). Only ever called after cpu::has_hw_aes() has been confirmed
// true; must not be called otherwise since the process may fault executing
// an unsupported instruction.
Block aes256_encrypt_block_arm(const SecretKey& key, const Block& block);
Block aes128_encrypt_block_arm(const SecretKey& key, const Block& block);

// Same operations, implemented with RV64 Zkne scalar crypto intrinsics
// (aes64es/aes64esm for the round transform, aes64ks1i/aes64ks2 for the key
// schedule — RISC-V has dedicated key-schedule-assist instructions, unlike
// ARM, so this backend computes its own schedule rather than sharing
// aes_key_schedule.hpp). Only ever called after cpu::has_hw_aes() has been
// confirmed true; must not be called otherwise since the process may fault
// executing an unsupported instruction.
Block aes256_encrypt_block_riscv(const SecretKey& key, const Block& block);
Block aes128_encrypt_block_riscv(const SecretKey& key, const Block& block);

// Hardware-accelerated forward cipher for whichever architecture this binary
// was built for — AES-NI on amd64, AArch64 Crypto Extensions on arm64, RV64
// Zkne on riscv64 (see aes_core_hw.cpp). The mode logic in
// aes256_ctr.cpp/aes_gcm.cpp calls only these, never the arch-specific
// _ni/_arm/_riscv functions above by name, so dispatch to a new architecture
// is a one-file change (aes_core_hw.cpp). Only ever called after
// cpu::has_hw_aes() has been confirmed true.
Block aes256_encrypt_block_hw(const SecretKey& key, const Block& block);
Block aes128_encrypt_block_hw(const SecretKey& key, const Block& block);

// GF(2^128) multiplication with the GCM reduction polynomial (NIST SP
// 800-38D Algorithm 1), branch-free/constant-time w.r.t. both operands.
Block gf128_mul(const Block& x, const Block& y);

// The GHASH function (NIST SP 800-38D §6.4): folds zero-padded 16-byte
// blocks of AAD then ciphertext into an accumulator via gf128_mul, then
// multiplies in the big-endian bit-length "length block".
Block ghash(const Block& h, const std::vector<std::byte>& aad, const std::vector<std::byte>& ciphertext);

// Throws LimitError if `plaintext_len` needs more 16-byte blocks than the
// CTR construction's 32-bit counter can address (see make_counter_block in
// aes256_ctr.cpp) — beyond that, a single encrypt()/decrypt() call would
// silently wrap the counter and reuse keystream within that call. Exposed
// here (taking a size, not a buffer) so tests can exercise the boundary
// without allocating a real ~64 GiB vector.
void validate_block_count(std::size_t plaintext_len);

// NIST SP 800-38D §8.3's recommended limit on the number of AES-GCM
// encryptions performed under one key when nonces are chosen at random: 2^32
// invocations, chosen so the cumulative probability of any nonce collision
// stays below 2^-32 — a tighter bar than the generic ~2^48 birthday-collision
// point (see DESIGN.md). Exposed here as a pure function of the prior
// invocation count (not tied to a real SecretKey) so the boundary can be unit
// tested directly, the same reason validate_block_count above takes a size
// rather than a buffer.
inline constexpr std::uint64_t kGcmInvocationLimit = std::uint64_t{1} << 32;
void check_gcm_invocation_count(std::uint64_t prior_invocations);

// SHA-256 per FIPS 180-4.
std::array<std::byte, 32> sha256(const std::byte* data, std::size_t len);

// HMAC-SHA256 per FIPS 198-1 / RFC 2104.
std::array<std::byte, 32> hmac_sha256(const std::byte* key, std::size_t key_len,
                                       const std::byte* data, std::size_t len);

// PBKDF2-HMAC-SHA256 per RFC 8018, with fixed dkLen=64 bytes (32 for AES
// wrapping subkey, 32 for HMAC subkey). Passphrase is a UTF-8 string.
std::array<std::byte, 64> pbkdf2_hmac_sha256(std::string_view passphrase,
                                              const std::byte* salt, std::size_t salt_len,
                                              std::uint32_t iterations);

// Constant-time byte array equality check (all bytes compared regardless of
// early match, preventing timing-oracle attacks on MAC verification).
bool constant_time_equal(const std::byte* a, const std::byte* b, std::size_t len) noexcept;

// Wipe a memory region with volatile writes (prevents compiler dead-store
// elimination). Used for clearing sensitive buffers after use.
void secure_wipe(std::byte* data, std::size_t len) noexcept;

// Wipes [data, data+len) on scope exit, including via exception unwinding.
// A backstop for scratch key-derivative buffers (e.g. PBKDF2 output) where a
// manual secure_wipe() call for the "wipe as soon as no longer needed"
// property could otherwise be skipped by an early throw or return.
class ScopedWipe {
public:
    ScopedWipe(std::byte* data, std::size_t len) noexcept : data_(data), len_(len) {}
    ~ScopedWipe() { secure_wipe(data_, len_); }
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;
    ScopedWipe(ScopedWipe&&) = delete;
    ScopedWipe& operator=(ScopedWipe&&) = delete;

private:
    std::byte* data_;
    std::size_t len_;
};

} // namespace aeslib::detail

namespace aeslib::cpu {

// True if the current CPU advertises a hardware AES acceleration extension:
// AES-NI (CPUID.1:ECX.AESNI, bit 25) on amd64, or AArch64 Crypto Extensions
// (HWCAP_AES / hw.optional.arm.FEAT_AES / PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE,
// depending on OS) on arm64. Computed once and memoized; safe to call
// repeatedly.
bool has_hw_aes();

} // namespace aeslib::cpu

namespace aeslib::rng {

// Fills `buffer` with cryptographically secure random bytes from the OS
// CSPRNG (BCryptGenRandom on Windows, getrandom(2) on Linux/other POSIX).
// Throws IoError if the OS source is unavailable or returns an error.
void fill_random(std::byte* buffer, std::size_t size);

} // namespace aeslib::rng
