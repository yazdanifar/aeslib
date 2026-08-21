#include <stdexcept>

#include "internal.hpp"

// The single seam that knows this library has more than one hardware AES
// backend. aes256_ctr.cpp and aes_gcm.cpp call only the arch-neutral
// aesNNN_encrypt_block_hw() functions below — never aesNNN_encrypt_block_ni()
// or aesNNN_encrypt_block_arm() directly — so adding a third architecture
// (see DESIGN.md) means adding one more aes_core_*.cpp and one more #elif
// here, with zero changes to the CTR/GCM mode logic.
//
// Only ever called after cpu::has_hw_aes() has confirmed this architecture's
// hardware path is safe to use; the #else branch is unreachable in a correct
// build (no architecture both lacks a real _ni/_arm implementation and has
// cpu::has_hw_aes() return true), kept as a loud failure rather than silent
// wrong output if that invariant is ever violated.

namespace aeslib::detail {

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

Block aes256_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes256_encrypt_block_ni(key, block); }
Block aes128_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes128_encrypt_block_ni(key, block); }

#elif defined(__aarch64__) || defined(_M_ARM64)

Block aes256_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes256_encrypt_block_arm(key, block); }
Block aes128_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes128_encrypt_block_arm(key, block); }

#elif defined(__riscv) && __riscv_xlen == 64

Block aes256_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes256_encrypt_block_riscv(key, block); }
Block aes128_encrypt_block_hw(const SecretKey& key, const Block& block) { return aes128_encrypt_block_riscv(key, block); }

#else

Block aes256_encrypt_block_hw(const SecretKey&, const Block&) {
    throw std::logic_error("aes256_encrypt_block_hw called on an architecture with no hardware AES backend");
}
Block aes128_encrypt_block_hw(const SecretKey&, const Block&) {
    throw std::logic_error("aes128_encrypt_block_hw called on an architecture with no hardware AES backend");
}

#endif

} // namespace aeslib::detail
