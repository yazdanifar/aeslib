#pragma once

// Internal-only declarations shared between the library's .cpp files. Not
// part of the public API in include/aeslib/.

#include <array>
#include <cstddef>
#include <cstdint>

#include "aeslib/key.hpp"

namespace aeslib::detail {

inline constexpr std::size_t kBlockSizeBytes = 16;
using Block = std::array<std::byte, kBlockSizeBytes>;

// Software AES-256 forward cipher (encryption direction only — CTR mode
// never needs AES decryption, see aes256_ctr.hpp). Pure, portable C++.
Block aes256_encrypt_block_soft(const SecretKey& key, const Block& block);

// The software backend's constant-time GF(2^8)-inversion S-box (see
// src/aes_core_soft.cpp). Exposed here purely so tests can check it against
// the canonical AES S-box table for all 256 inputs; not part of the public
// API.
std::uint8_t ct_sbox(std::uint8_t x);

// Same operation, implemented with AES-NI intrinsics. Only ever called after
// cpu::has_aes_ni() has been confirmed true; must not be called otherwise
// since the process may fault executing an unsupported instruction.
Block aes256_encrypt_block_ni(const SecretKey& key, const Block& block);

// Throws LimitError if `plaintext_len` needs more 16-byte blocks than the
// CTR construction's 32-bit counter can address (see make_counter_block in
// aes256_ctr.cpp) — beyond that, a single encrypt()/decrypt() call would
// silently wrap the counter and reuse keystream within that call. Exposed
// here (taking a size, not a buffer) so tests can exercise the boundary
// without allocating a real ~64 GiB vector.
void validate_block_count(std::size_t plaintext_len);

} // namespace aeslib::detail

namespace aeslib::cpu {

// True if the current CPU advertises AES-NI support (CPUID.1:ECX.AESNI,
// bit 25). Computed once and memoized; safe to call repeatedly.
bool has_aes_ni();

} // namespace aeslib::cpu

namespace aeslib::rng {

// Fills `buffer` with cryptographically secure random bytes from the OS
// CSPRNG (BCryptGenRandom on Windows, getrandom(2) on Linux/other POSIX).
// Throws IoError if the OS source is unavailable or returns an error.
void fill_random(std::byte* buffer, std::size_t size);

} // namespace aeslib::rng
