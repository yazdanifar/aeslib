#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <type_traits>
#include <vector>

#include "aeslib/byte_view.hpp"
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

    // Bonus: generic support for other types via templates (see
    // byte_view.hpp and DESIGN.md). Same idea as Aes256Ctr's template
    // encrypt(): accepts any byte-viewable T for the plaintext. `aad`
    // deliberately stays std::vector<std::byte> — it's a secondary
    // parameter, not the plaintext this bonus is about.
    template <typename T, typename = std::enable_if_t<
                               detail::is_byte_viewable_v<T> &&
                               !std::is_same_v<T, std::vector<std::byte>>>>
    static GcmContainer encrypt(const SecretKey& key, const T& plaintext,
                                 const std::vector<std::byte>& aad = {}) {
        return encrypt(key, detail::to_byte_vector(plaintext), aad);
    }

    // Decrypts a container previously produced by encrypt() under `key`,
    // verifying the authentication tag against the same `aad` before
    // decrypting. Throws AuthenticationError if the tag doesn't verify
    // (wrong key/nonce/aad, or a tampered ciphertext/tag) — the ciphertext is
    // never decrypted before authentication succeeds.
    static std::vector<std::byte> decrypt(const SecretKey& key, const GcmContainer& container,
                                           const std::vector<std::byte>& aad = {});

    // Bonus: generic support for other types via templates. Decrypts and
    // authenticates, then reinterprets the plaintext bytes as T (see
    // byte_view.hpp). Call as decrypt_as<T>(key, container[, aad]); throws
    // AuthenticationError first (same as decrypt()), then FormatError if the
    // authenticated byte count doesn't match what T requires.
    template <typename T, typename = std::enable_if_t<detail::is_byte_viewable_v<T>>>
    static T decrypt_as(const SecretKey& key, const GcmContainer& container,
                         const std::vector<std::byte>& aad = {}) {
        return detail::from_byte_vector<T>(decrypt(key, container, aad));
    }
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
