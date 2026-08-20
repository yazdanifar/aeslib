#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "aeslib/key.hpp"

namespace aeslib {

// AES-GCM (NIST SP 800-38D): an authenticated mode, unlike Aes256Ctr. Works
// with both AES-128 and AES-256 keys (dispatched on SecretKey::size_bytes()).
//
// Wire format (GcmContainer, all integers little-endian):
//   bytes 0..3   magic      "AESG"
//   byte  4      version    currently kGcmContainerVersion
//   bytes 5..16  nonce      12 bytes, the GCM IV
//   bytes 17..32 tag        16-byte authentication tag
//   bytes 33..40 ct_len     uint64_t, ciphertext length in bytes
//   bytes 41..   ciphertext ct_len bytes
//
// A distinct magic from Container's "AESC" so the two file types can't be
// confused with each other.
inline constexpr std::size_t kGcmNonceSizeBytes = 12; // 96-bit IV (recommended case, SP 800-38D)
inline constexpr std::size_t kGcmTagSizeBytes = 16;
inline constexpr std::uint8_t kGcmContainerVersion = 1;

struct GcmContainer {
    std::array<std::byte, kGcmNonceSizeBytes> nonce{};
    std::array<std::byte, kGcmTagSizeBytes> tag{};
    std::vector<std::byte> ciphertext;
};

// AES-GCM encryption/decryption. Stateless with respect to key material, same
// shape as Aes256Ctr.
class AesGcm final {
public:
    // Encrypts `plaintext` under `key` (AES-128 or AES-256), generating a
    // fresh random 96-bit nonce internally, with optional additional
    // authenticated data `aad` (authenticated but not encrypted). See
    // DESIGN.md for the nonce strategy, including why nonce reuse under GCM
    // is a strictly worse failure mode than under CTR.
    static GcmContainer encrypt(const SecretKey& key, const std::vector<std::byte>& plaintext,
                                 const std::vector<std::byte>& aad = {});

    // Decrypts a container previously produced by encrypt() under `key`,
    // verifying the authentication tag against the same `aad` before
    // decrypting. Throws AuthenticationError if the tag doesn't verify
    // (wrong key/nonce/aad, or a tampered ciphertext/tag) — the ciphertext is
    // never decrypted before authentication succeeds.
    static std::vector<std::byte> decrypt(const SecretKey& key, const GcmContainer& container,
                                           const std::vector<std::byte>& aad = {});
};

// Serializes a GcmContainer to bytes using the wire format documented above.
std::vector<std::byte> serialize(const GcmContainer& container);

// Parses bytes previously produced by serialize(). Throws FormatError on a
// bad magic, unsupported version, or truncated/malformed input.
GcmContainer deserialize_gcm(const std::vector<std::byte>& data);

// Convenience file I/O built on serialize/deserialize_gcm plus plain file reads.
void save_gcm_container(const GcmContainer& container, const std::filesystem::path& path);
GcmContainer load_gcm_container(const std::filesystem::path& path);

} // namespace aeslib
