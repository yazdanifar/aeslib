#include "aeslib/aes_gcm.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>

#include "aeslib/backend.hpp"
#include "aeslib/container.hpp" // read_file/write_file
#include "aeslib/exceptions.hpp"
#include "internal.hpp"

namespace aeslib {

namespace {

using detail::Block;
using detail::kBlockSizeBytes;

// GCM's own block-counter limit is one less than CTR's: the 32-bit counter
// addresses blocks 1..2^32-1, but counter value 1 (J0) is reserved for
// encrypting the tag, so only 2^32-2 blocks of keystream (counters 2..2^32-1)
// are available for plaintext/ciphertext per invocation.
constexpr std::uint64_t kMaxBlocks = (std::uint64_t{1} << 32) - 2;
constexpr std::uint64_t kMaxPlaintextBytes = kMaxBlocks * kBlockSizeBytes;

// aesNNN_encrypt_block_hw() resolves to the AES-NI or ARM Crypto Extensions
// backend depending on the build's target architecture (see aes_core_hw.cpp)
// — this file never names either directly.
Block encrypt_block(const SecretKey& key, const Block& block) {
    const bool hw = active_backend() == Backend::Hardware;
    if (key.size_bytes() == 16) {
        return hw ? detail::aes128_encrypt_block_hw(key, block) : detail::aes128_encrypt_block_soft(key, block);
    }
    return hw ? detail::aes256_encrypt_block_hw(key, block) : detail::aes256_encrypt_block_soft(key, block);
}

// Same nonce||counter construction as Aes256Ctr's make_counter_block (see
// aes256_ctr.cpp) — a 96-bit nonce plus a 32-bit big-endian counter.
Block make_counter_block(const std::array<std::byte, kGcmNonceSizeBytes>& nonce, std::uint32_t counter) {
    Block block{};
    for (std::size_t i = 0; i < kGcmNonceSizeBytes; ++i) block[i] = nonce[i];
    block[12] = static_cast<std::byte>((counter >> 24) & 0xff);
    block[13] = static_cast<std::byte>((counter >> 16) & 0xff);
    block[14] = static_cast<std::byte>((counter >> 8) & 0xff);
    block[15] = static_cast<std::byte>(counter & 0xff);
    return block;
}

// GCM keystream XOR, starting at counter=2 (counter=1 is J0, reserved for the
// tag). Self-inverse, same as CTR's apply_keystream, so this implements both
// encryption and decryption of the ciphertext body.
std::vector<std::byte> apply_keystream(const SecretKey& key, const std::array<std::byte, kGcmNonceSizeBytes>& nonce,
                                        const std::vector<std::byte>& input) {
    std::vector<std::byte> output(input.size());
    std::uint32_t counter = 2;
    for (std::size_t offset = 0; offset < input.size(); offset += kBlockSizeBytes, ++counter) {
        const Block keystream = encrypt_block(key, make_counter_block(nonce, counter));
        const std::size_t chunk = std::min(kBlockSizeBytes, input.size() - offset);
        for (std::size_t i = 0; i < chunk; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
    }
    return output;
}

std::array<std::byte, kGcmNonceSizeBytes> generate_nonce() {
    std::array<std::byte, kGcmNonceSizeBytes> nonce{};
    rng::fill_random(nonce.data(), nonce.size());
    return nonce;
}

void validate_block_count(std::size_t plaintext_len) {
    if (static_cast<std::uint64_t>(plaintext_len) > kMaxPlaintextBytes) {
        throw LimitError(
            "plaintext exceeds the limit addressable by this GCM construction's 32-bit block counter");
    }
}

Block xor_blocks(const Block& a, const Block& b) {
    Block out{};
    for (std::size_t i = 0; i < kBlockSizeBytes; ++i) out[i] = static_cast<std::byte>(a[i] ^ b[i]);
    return out;
}

// Computes the authentication tag for (key, nonce, aad, ciphertext):
// H = E(K, 0^128); J0 = nonce || 1; tag = E(K, J0) XOR GHASH_H(aad, ciphertext).
Block compute_tag(const SecretKey& key, const std::array<std::byte, kGcmNonceSizeBytes>& nonce,
                   const std::vector<std::byte>& aad, const std::vector<std::byte>& ciphertext) {
    const Block zero{};
    Block h = encrypt_block(key, zero);
    const Block j0 = make_counter_block(nonce, 1);
    const Block s = detail::ghash(h, aad, ciphertext);
    Block e_j0 = encrypt_block(key, j0);
    const Block tag = xor_blocks(e_j0, s);
    detail::secure_wipe(h.data(), h.size());
    detail::secure_wipe(e_j0.data(), e_j0.size());
    return tag;
}

} // namespace

GcmContainer AesGcm::encrypt(const SecretKey& key, const std::vector<std::byte>& plaintext,
                              const std::vector<std::byte>& aad) {
    validate_block_count(plaintext.size());
    const auto nonce = generate_nonce();

    GcmContainer container;
    container.nonce = nonce;
    container.ciphertext = apply_keystream(key, nonce, plaintext);
    container.tag = compute_tag(key, nonce, aad, container.ciphertext);
    return container;
}

std::vector<std::byte> AesGcm::decrypt(const SecretKey& key, const GcmContainer& container,
                                        const std::vector<std::byte>& aad) {
    validate_block_count(container.ciphertext.size());

    const Block expected_tag = compute_tag(key, container.nonce, aad, container.ciphertext);
    if (!detail::constant_time_equal(expected_tag.data(), container.tag.data(), kGcmTagSizeBytes)) {
        throw AuthenticationError("GCM authentication failed: wrong key/nonce/aad, or tampered ciphertext/tag");
    }

    return apply_keystream(key, container.nonce, container.ciphertext);
}

namespace {
constexpr char kGcmMagic[4] = {'A', 'E', 'S', 'G'};
constexpr std::size_t kGcmHeaderSize = 4 + 1 + kGcmNonceSizeBytes + kGcmTagSizeBytes + 8; // magic+version+nonce+tag+ct_len
} // namespace

std::vector<std::byte> serialize(const GcmContainer& container) {
    std::vector<std::byte> out;
    out.reserve(kGcmHeaderSize + container.ciphertext.size());

    for (char c : kGcmMagic) out.push_back(static_cast<std::byte>(c));
    out.push_back(static_cast<std::byte>(kGcmContainerVersion));
    out.insert(out.end(), container.nonce.begin(), container.nonce.end());
    out.insert(out.end(), container.tag.begin(), container.tag.end());

    std::uint64_t ct_len = container.ciphertext.size();
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::byte>((ct_len >> (8 * i)) & 0xff));
    }

    out.insert(out.end(), container.ciphertext.begin(), container.ciphertext.end());
    return out;
}

GcmContainer deserialize_gcm(const std::vector<std::byte>& data) {
    if (data.size() < kGcmHeaderSize) {
        throw FormatError("GCM container truncated: missing header");
    }

    for (std::size_t i = 0; i < 4; ++i) {
        if (static_cast<char>(data[i]) != kGcmMagic[i]) {
            throw FormatError("GCM container has bad magic bytes");
        }
    }

    auto version = static_cast<std::uint8_t>(data[4]);
    if (version != kGcmContainerVersion) {
        throw FormatError("unsupported GCM container version: " + std::to_string(version));
    }

    GcmContainer container;
    std::size_t offset = 5;
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset), kGcmNonceSizeBytes, container.nonce.begin());
    offset += kGcmNonceSizeBytes;
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset), kGcmTagSizeBytes, container.tag.begin());
    offset += kGcmTagSizeBytes;

    std::uint64_t ct_len = 0;
    for (int i = 0; i < 8; ++i) {
        ct_len |= static_cast<std::uint64_t>(data[offset + static_cast<std::size_t>(i)]) << (8 * i);
    }
    offset += 8;

    if (data.size() - offset != ct_len) {
        throw FormatError("GCM container ciphertext length mismatch");
    }

    container.ciphertext.assign(data.begin() + static_cast<std::ptrdiff_t>(offset), data.end());
    return container;
}

void save_gcm_container(const GcmContainer& container, const std::filesystem::path& path) {
    write_file(path, serialize(container));
}

GcmContainer load_gcm_container(const std::filesystem::path& path) { return deserialize_gcm(read_file(path)); }

} // namespace aeslib
