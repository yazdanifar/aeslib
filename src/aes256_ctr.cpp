#include "aeslib/aes256_ctr.hpp"

#include <algorithm>
#include <cstdint>

#include "aeslib/backend.hpp"
#include "internal.hpp"

namespace aeslib {

namespace {

using detail::Block;
using detail::kBlockSizeBytes;

Block encrypt_block(const SecretKey& key, const Block& block) {
    // Decided once per call via the runtime CPUID check in cpu_detect.cpp —
    // never a compile-time #ifdef, so the same binary is correct whether or
    // not the host CPU has AES-NI.
    return active_backend() == Backend::Hardware ? detail::aes256_encrypt_block_ni(key, block)
                                                  : detail::aes256_encrypt_block_soft(key, block);
}

// Builds the 16-byte CTR input block from the container's 96-bit nonce and a
// 32-bit big-endian block counter (the same nonce||counter construction used
// by AES-GCM). See DESIGN.md for why this split was chosen.
Block make_counter_block(const std::array<std::byte, kNonceSizeBytes>& nonce, std::uint32_t counter) {
    Block block{};
    for (std::size_t i = 0; i < kNonceSizeBytes; ++i) block[i] = nonce[i];
    block[12] = static_cast<std::byte>((counter >> 24) & 0xff);
    block[13] = static_cast<std::byte>((counter >> 16) & 0xff);
    block[14] = static_cast<std::byte>((counter >> 8) & 0xff);
    block[15] = static_cast<std::byte>(counter & 0xff);
    return block;
}

// CTR keystream XOR is its own inverse, so this one function implements both
// Aes256Ctr::encrypt and Aes256Ctr::decrypt.
std::vector<std::byte> apply_keystream(const SecretKey& key, const std::array<std::byte, kNonceSizeBytes>& nonce,
                                        const std::vector<std::byte>& input) {
    std::vector<std::byte> output(input.size());
    std::uint32_t counter = 0;
    for (std::size_t offset = 0; offset < input.size(); offset += kBlockSizeBytes, ++counter) {
        const Block keystream = encrypt_block(key, make_counter_block(nonce, counter));
        const std::size_t chunk = std::min(kBlockSizeBytes, input.size() - offset);
        for (std::size_t i = 0; i < chunk; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
    }
    return output;
}

std::array<std::byte, kNonceSizeBytes> generate_nonce() {
    std::array<std::byte, kNonceSizeBytes> nonce{};
    rng::fill_random(nonce.data(), nonce.size());
    return nonce;
}

} // namespace

Container Aes256Ctr::encrypt(const SecretKey& key, const std::vector<std::byte>& plaintext) {
    const auto nonce = generate_nonce();
    Container container;
    container.nonce = nonce;
    container.ciphertext = apply_keystream(key, nonce, plaintext);
    return container;
}

std::vector<std::byte> Aes256Ctr::decrypt(const SecretKey& key, const Container& container) {
    return apply_keystream(key, container.nonce, container.ciphertext);
}

} // namespace aeslib
