#pragma once

// Internal-only declarations shared between the library's .cpp files. Not
// part of the public API in include/aeslib/.

#include <array>
#include <cstddef>

#include "aeslib/key.hpp"

namespace aeslib::detail {

inline constexpr std::size_t kBlockSizeBytes = 16;
using Block = std::array<std::byte, kBlockSizeBytes>;

// Software AES-256 forward cipher (encryption direction only — CTR mode
// never needs AES decryption, see aes256_ctr.hpp). Pure, portable C++.
Block aes256_encrypt_block_soft(const SecretKey& key, const Block& block);

// Same operation, implemented with AES-NI intrinsics. Only ever called after
// cpu::has_aes_ni() has been confirmed true; must not be called otherwise
// since the process may fault executing an unsupported instruction.
Block aes256_encrypt_block_ni(const SecretKey& key, const Block& block);

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
