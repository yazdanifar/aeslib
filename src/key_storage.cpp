#include "aeslib/key.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/container.hpp"
#include "aeslib/exceptions.hpp"
#include "internal.hpp"

namespace aeslib {

namespace {

// Wrapped-key file format (101 bytes total):
// 0..3    magic "AESW" (4 bytes)
// 4       version (1 byte)
// 5..20   salt (16 bytes)
// 21..24  iterations (4 bytes, little-endian)
// 25..36  nonce (12 bytes)
// 37..68  wrapped_key (32 bytes, AES-256-CTR encrypted)
// 69..100 hmac_tag (32 bytes)

constexpr std::size_t kWrappedKeyFileSize = 101;
constexpr std::uint8_t kWrappedKeyFileMagic[4] = {'A', 'E', 'S', 'W'};
constexpr std::uint8_t kWrappedKeyFileVersion = 1;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 32;

} // namespace

void SecretKey::save_to_file_encrypted(const std::filesystem::path& path, std::string_view passphrase,
                                        std::uint32_t iterations) const {
    // Generate a random salt.
    std::array<std::byte, kSaltSize> salt;
    rng::fill_random(salt.data(), salt.size());

    // Derive wrapping key and MAC key via PBKDF2.
    std::array<std::byte, 64> derived = detail::pbkdf2_hmac_sha256(passphrase, salt.data(), salt.size(), iterations);

    // First 32 bytes: AES-256-CTR wrapping key.
    // Next 32 bytes: HMAC-SHA256 key.
    SecretKey wrap_key; // Local key to hold the derived AES key; gets wiped on destruction.
    std::memcpy(wrap_key.bytes_.data(), derived.data(), kKeySizeBytes);

    // Generate nonce for AES-256-CTR.
    std::array<std::byte, kNonceSize> nonce;
    rng::fill_random(nonce.data(), nonce.size());

    // Encrypt the raw key using AES-256-CTR with the derived wrap_key.
    std::vector<std::byte> plaintext_key(detail::key_bytes(*this).begin(), detail::key_bytes(*this).end());
    Container wrapped_container = Aes256Ctr::encrypt(wrap_key, plaintext_key);
    detail::secure_wipe(plaintext_key.data(), plaintext_key.size());

    // Sanity check: the container's ciphertext should be exactly kKeySizeBytes.
    if (wrapped_container.ciphertext.size() != kKeySizeBytes) {
        throw IoError("internal: wrapped key ciphertext size mismatch");
    }

    // wrap_key will be wiped on destruction (it's a SecretKey).

    // Build the wrapped-key file structure (before the tag).
    std::array<std::byte, 69> plaintext_part; // 4 magic + 1 version + 16 salt + 4 iterations + 12 nonce + 32 encrypted
    std::size_t offset = 0;

    // Magic.
    std::memcpy(&plaintext_part[offset], kWrappedKeyFileMagic, 4);
    offset += 4;

    // Version.
    plaintext_part[offset++] = static_cast<std::byte>(kWrappedKeyFileVersion);

    // Salt.
    std::memcpy(&plaintext_part[offset], salt.data(), kSaltSize);
    offset += kSaltSize;

    // Iterations (little-endian).
    plaintext_part[offset++] = static_cast<std::byte>(iterations);
    plaintext_part[offset++] = static_cast<std::byte>(iterations >> 8);
    plaintext_part[offset++] = static_cast<std::byte>(iterations >> 16);
    plaintext_part[offset++] = static_cast<std::byte>(iterations >> 24);

    // Nonce (from the encrypted container).
    std::memcpy(&plaintext_part[offset], wrapped_container.nonce.data(), kNonceSize);
    offset += kNonceSize;

    // Wrapped key ciphertext.
    std::memcpy(&plaintext_part[offset], wrapped_container.ciphertext.data(), kKeySizeBytes);
    offset += kKeySizeBytes;

    if (offset != 69) {
        throw IoError("internal: wrapped key file layout error");
    }

    // Compute HMAC-SHA256 over the plaintext_part using the MAC subkey.
    std::array<std::byte, 32> mac_key_array;
    std::memcpy(mac_key_array.data(), &derived[kKeySizeBytes], kKeySizeBytes);
    std::array<std::byte, 32> tag = detail::hmac_sha256(mac_key_array.data(), mac_key_array.size(),
                                                         plaintext_part.data(), plaintext_part.size());
    detail::secure_wipe(mac_key_array.data(), mac_key_array.size());

    // Wipe the derived buffer (no longer needed after tag computation).
    detail::secure_wipe(derived.data(), derived.size());

    // Write file: plaintext_part || tag.
    int fd = -1;
#if defined(_WIN32)
    HANDLE h = ::CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw IoError("failed to create encrypted key file: " + path.string());
    }
    DWORD written = 0;
    const bool ok = ::WriteFile(h, plaintext_part.data(), static_cast<DWORD>(plaintext_part.size()), &written, nullptr) &&
                     written == plaintext_part.size() &&
                     ::WriteFile(h, tag.data(), static_cast<DWORD>(tag.size()), &written, nullptr) &&
                     written == tag.size();
    ::CloseHandle(h);
    if (!ok) {
        throw IoError("failed to write encrypted key file: " + path.string());
    }
#else
    fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        throw IoError("failed to create encrypted key file: " + path.string());
    }
    bool ok = true;
    auto* data = reinterpret_cast<const char*>(plaintext_part.data());
    std::size_t written = 0;
    while (written < plaintext_part.size()) {
        const ssize_t n = ::write(fd, data + written, plaintext_part.size() - written);
        if (n < 0) {
            ok = false;
            break;
        }
        written += static_cast<std::size_t>(n);
    }
    if (ok) {
        data = reinterpret_cast<const char*>(tag.data());
        written = 0;
        while (written < tag.size()) {
            const ssize_t n = ::write(fd, data + written, tag.size() - written);
            if (n < 0) {
                ok = false;
                break;
            }
            written += static_cast<std::size_t>(n);
        }
    }
    ::close(fd);
    if (!ok) {
        throw IoError("failed to write encrypted key file: " + path.string());
    }
#endif
}

SecretKey SecretKey::load_from_file_encrypted(const std::filesystem::path& path, std::string_view passphrase) {
    // Read entire file.
    std::vector<std::byte> file_data = read_file(path); // free function in container.hpp

    if (file_data.size() != kWrappedKeyFileSize) {
        throw FormatError("encrypted key file has wrong size: expected " + std::to_string(kWrappedKeyFileSize) +
                           ", got " + std::to_string(file_data.size()));
    }

    // Parse fixed structure.
    std::size_t offset = 0;

    // Magic.
    if (std::memcmp(&file_data[offset], kWrappedKeyFileMagic, 4) != 0) {
        throw FormatError("encrypted key file has wrong magic");
    }
    offset += 4;

    // Version.
    std::uint8_t version = static_cast<std::uint8_t>(file_data[offset++]);
    if (version != kWrappedKeyFileVersion) {
        throw FormatError("encrypted key file has unsupported version: " + std::to_string(version));
    }

    // Salt.
    std::array<std::byte, kSaltSize> salt;
    std::memcpy(salt.data(), &file_data[offset], kSaltSize);
    offset += kSaltSize;

    // Iterations (little-endian).
    std::uint32_t b0 = static_cast<std::uint8_t>(file_data[offset++]);
    std::uint32_t b1 = static_cast<std::uint8_t>(file_data[offset++]);
    std::uint32_t b2 = static_cast<std::uint8_t>(file_data[offset++]);
    std::uint32_t b3 = static_cast<std::uint8_t>(file_data[offset++]);
    std::uint32_t iterations = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);

    // Nonce.
    std::array<std::byte, kNonceSize> nonce;
    std::memcpy(nonce.data(), &file_data[offset], kNonceSize);
    offset += kNonceSize;

    // Wrapped key ciphertext.
    std::array<std::byte, kKeySizeBytes> wrapped_ciphertext;
    std::memcpy(wrapped_ciphertext.data(), &file_data[offset], kKeySizeBytes);
    offset += kKeySizeBytes;

    // HMAC tag.
    std::array<std::byte, kTagSize> stored_tag;
    std::memcpy(stored_tag.data(), &file_data[offset], kTagSize);
    offset += kTagSize;

    if (offset != kWrappedKeyFileSize) {
        throw FormatError("encrypted key file layout error");
    }

    // Derive wrapping key and MAC key.
    std::array<std::byte, 64> derived = detail::pbkdf2_hmac_sha256(passphrase, salt.data(), salt.size(), iterations);

    // Extract MAC key (second 32 bytes) and verify tag.
    std::array<std::byte, 32> mac_key_array;
    std::memcpy(mac_key_array.data(), &derived[kKeySizeBytes], kKeySizeBytes);

    // Verify HMAC over the plaintext part (everything except the tag).
    std::array<std::byte, 32> computed_tag =
        detail::hmac_sha256(mac_key_array.data(), mac_key_array.size(), &file_data[0], 69);

    if (!detail::constant_time_equal(computed_tag.data(), stored_tag.data(), kTagSize)) {
        detail::secure_wipe(derived.data(), derived.size());
        detail::secure_wipe(mac_key_array.data(), mac_key_array.size());
        throw AuthenticationError("encrypted key file authentication failed: wrong passphrase or corrupted file");
    }

    // Extract AES wrapping key (first 32 bytes) and decrypt.
    SecretKey wrap_key;
    std::memcpy(wrap_key.bytes_.data(), derived.data(), kKeySizeBytes);

    // Construct a Container to decrypt the wrapped key.
    Container wrapped_container;
    wrapped_container.nonce = nonce;
    wrapped_container.ciphertext = std::vector<std::byte>(wrapped_ciphertext.begin(), wrapped_ciphertext.end());

    std::vector<std::byte> decrypted_bytes = Aes256Ctr::decrypt(wrap_key, wrapped_container);

    if (decrypted_bytes.size() != kKeySizeBytes) {
        throw FormatError("encrypted key file: decrypted key has wrong size");
    }

    // Construct and return the key.
    SecretKey result;
    std::memcpy(result.bytes_.data(), decrypted_bytes.data(), kKeySizeBytes);

    // Wipe derived material.
    detail::secure_wipe(derived.data(), derived.size());
    detail::secure_wipe(mac_key_array.data(), mac_key_array.size());
    detail::secure_wipe(decrypted_bytes.data(), decrypted_bytes.size());

    return result;
}

} // namespace aeslib
