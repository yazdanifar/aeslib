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

// Lower bound on an accepted iteration count, per NIST SP 800-132's PBKDF2
// floor. Rejecting only iterations == 0 isn't enough: a corrupted or
// deliberately hostile file could claim a small-but-nonzero count (e.g. 1)
// and load_from_file_encrypted would derive the MAC subkey and decrypt with
// negligible stretching, which matters most if this ever sits behind a
// decrypt-with-passphrase oracle — the same shape of bug the age encryption
// tool's scrypt recipient had (github.com/FiloSottile/age/issues/417): a
// file's own header controlling its KDF work factor lets an attacker make
// their own guesses artificially cheap. The floor is deliberately below
// kDefaultPbkdf2Iterations so a caller who explicitly wants a faster,
// still-reasonable iteration count isn't forced up to 600,000.
constexpr std::uint32_t kMinPbkdf2Iterations = 1000;

// Upper bound on an accepted iteration count: far above the 600,000 default
// (kDefaultPbkdf2Iterations), so no legitimate caller or file is ever
// rejected, but low enough to bound the worst-case PBKDF2 cost that
// load_from_file_encrypted must pay *before* it can authenticate the file
// (the MAC subkey needs PBKDF2 output, so a huge iteration count in the
// file's untrusted header would otherwise force unbounded work ahead of any
// tamper/wrong-passphrase check).
constexpr std::uint32_t kMaxPbkdf2Iterations = 50'000'000;

} // namespace

void SecretKey::save_to_file_encrypted(const std::filesystem::path& path, std::string_view passphrase,
                                        std::uint32_t iterations) const {
    // Too few iterations weakens or (at 0) entirely defeats PBKDF2
    // stretching. NIST SP 800-132 floors PBKDF2 at 1000 iterations.
    if (iterations < kMinPbkdf2Iterations) {
        throw LimitError("PBKDF2 iteration count must be at least " +
                          std::to_string(kMinPbkdf2Iterations));
    }

    // Generate a random salt.
    std::array<std::byte, kSaltSize> salt;
    rng::fill_random(salt.data(), salt.size());

    // Derive wrapping key and MAC key via PBKDF2.
    std::array<std::byte, 64> derived = detail::pbkdf2_hmac_sha256(passphrase, salt.data(), salt.size(), iterations);
    detail::ScopedWipe wipe_derived(derived.data(), derived.size());

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
    detail::ScopedWipe wipe_mac_key(mac_key_array.data(), mac_key_array.size());
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

    // Reject a too-small or unreasonably large iteration count *before*
    // running PBKDF2: iterations comes straight from the file's untrusted
    // header and is needed to derive the MAC subkey, so it's used ahead of
    // any authentication check. Without the upper bound, a corrupted or
    // hostile file could force an effectively unbounded PBKDF2 computation
    // before load_from_file_encrypted ever gets a chance to reject it;
    // without the lower bound, such a file could instead claim a
    // negligible iteration count and make brute-forcing the passphrase
    // against this file artificially cheap (see kMinPbkdf2Iterations above).
    if (iterations < kMinPbkdf2Iterations || iterations > kMaxPbkdf2Iterations) {
        throw FormatError("encrypted key file has an invalid iteration count: " + std::to_string(iterations));
    }

    // Derive wrapping key and MAC key.
    std::array<std::byte, 64> derived = detail::pbkdf2_hmac_sha256(passphrase, salt.data(), salt.size(), iterations);
    detail::ScopedWipe wipe_derived(derived.data(), derived.size());

    // Extract MAC key (second 32 bytes) and verify tag.
    std::array<std::byte, 32> mac_key_array;
    detail::ScopedWipe wipe_mac_key(mac_key_array.data(), mac_key_array.size());
    std::memcpy(mac_key_array.data(), &derived[kKeySizeBytes], kKeySizeBytes);

    // Verify HMAC over the plaintext part (everything except the tag).
    std::array<std::byte, 32> computed_tag =
        detail::hmac_sha256(mac_key_array.data(), mac_key_array.size(), &file_data[0], 69);

    if (!detail::constant_time_equal(computed_tag.data(), stored_tag.data(), kTagSize)) {
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
    detail::ScopedWipe wipe_decrypted(decrypted_bytes.data(), decrypted_bytes.size());

    if (decrypted_bytes.size() != kKeySizeBytes) {
        throw FormatError("encrypted key file: decrypted key has wrong size");
    }

    // Construct and return the key. derived/mac_key_array/decrypted_bytes
    // are wiped by their ScopedWipe guards as this scope unwinds.
    SecretKey result;
    std::memcpy(result.bytes_.data(), decrypted_bytes.data(), kKeySizeBytes);

    return result;
}

} // namespace aeslib
