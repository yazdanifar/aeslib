#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string_view>

namespace aeslib {

inline constexpr std::size_t kKeySizeBytes = 32; // AES-256; storage capacity for both key sizes
inline constexpr std::uint32_t kDefaultPbkdf2Iterations = 600'000; // OWASP recommendation

// Logical key size. The AES-128 variant only uses the first 16 bytes of the
// underlying (always 32-byte) storage — see SecretKey's `bytes_` comment.
enum class KeySize : std::uint8_t { Aes128 = 16, Aes256 = 32 };

class SecretKey;

namespace detail {
// SecretKey's sole raw-byte access seam. Only the *name* is declared here:
// the definition — and the detail::key_bytes() / key_from_bytes() /
// consume_gcm_invocation() wrappers over it — live in src/internal.hpp,
// which nothing outside the library's own .cpp files and the test binary
// includes. So a consumer holding only these public headers can name this
// type but has no member of it to call, and therefore no way to read, copy,
// or print raw key bytes. That's deliberate: an ordinary caller has no need
// to see them at all (aes256_ctr.cpp only ever passes SecretKey by const&
// down to the backends), and an ordinary getter would invite
// `auto leaked = key.bytes();` or `std::cout << key.bytes()[0];` — the kind
// of accidental copy/log that escapes wipe()/mlock() entirely. The one
// sanctioned way for a caller to get key material out of a SecretKey
// remains the explicit, deliberately-named save_to_file().
struct KeyAccess;
} // namespace detail

// Move-only holder for a raw AES-256 key. Copy is disabled so a key can't be
// accidentally duplicated; the backing bytes are wiped on destruction (and on
// move-from) so a key doesn't linger in memory longer than its owner is
// alive.
class SecretKey final {
public:
    // Generates a fresh 256-bit key using the platform CSPRNG (see
    // csprng.hpp) — never a general-purpose PRNG.
    [[nodiscard]] static SecretKey generate();

    // Same, but for the requested key size. The full kKeySizeBytes of
    // backing storage is always CSPRNG-filled regardless of `size` (see
    // `bytes_`); only the logical size marker differs.
    [[nodiscard]] static SecretKey generate(KeySize size);

    // Loads a key previously written by save_to_file(). File format
    // (version 2): version(1) || size_marker(1, 16 or 32) ||
    // size_marker bytes of key.
    [[nodiscard]] static SecretKey load_from_file(const std::filesystem::path& path);

    // The key's logical size (AES-128 or AES-256).
    [[nodiscard]] KeySize size() const noexcept;
    // Same, as a byte count (16 or 32) — convenience over static_cast<size_t>(size()).
    [[nodiscard]] std::size_t size_bytes() const noexcept;

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;
    ~SecretKey();

    // Writes the key to its own file, separate from any ciphertext. On
    // POSIX the file is created with 0600 permissions before any key bytes
    // are written.
    void save_to_file(const std::filesystem::path& path) const;

    // Writes the key to a passphrase-protected file via PBKDF2-HMAC-SHA256
    // key derivation, AES-256-CTR encryption, and HMAC-SHA256 authentication.
    // File format (version 2, 70 + key_size bytes): magic, version, key size
    // marker (16 or 32), salt (16 bytes), PBKDF2 iteration count, nonce,
    // encrypted key (key_size bytes), HMAC tag. Works for both AES-128 and
    // AES-256 keys — the wrapping key derived from the passphrase is always
    // AES-256, but only the caller's own key's logical size is ever wrapped
    // and persisted. See DESIGN.md. `iterations` defaults to 600,000 (OWASP
    // recommendation for password hashing).
    void save_to_file_encrypted(const std::filesystem::path& path, std::string_view passphrase,
                                 std::uint32_t iterations = kDefaultPbkdf2Iterations) const;

    // Loads a key previously written by save_to_file_encrypted(). Verifies the
    // HMAC tag before decrypting. Throws AuthenticationError if the passphrase
    // is wrong or the file has been tampered with; FormatError on structural
    // parse failure; IoError on filesystem failures.
    [[nodiscard]] static SecretKey load_from_file_encrypted(const std::filesystem::path& path,
                                                             std::string_view passphrase);

private:
    friend struct detail::KeyAccess;

    SecretKey();
    void wipe() noexcept;
    // Best-effort: pins/unpins the key's backing pages against being paged
    // to swap/disk while the key is alive. Failures (e.g. RLIMIT_MEMLOCK on
    // POSIX) are deliberately ignored rather than propagated — this is
    // defense-in-depth on top of wipe()/non-copyability, not a hard
    // requirement, and key generation must not start failing on hosts where
    // the memlock limit is tight. See DESIGN.md's threat-model section.
    void lock_memory() noexcept;
    void unlock_memory() noexcept;

    // Always the full 32-byte capacity, regardless of size_: an AES-128 key
    // only ever reads/saves the first 16 bytes, but the remaining 16 are
    // still real CSPRNG output, locked and wiped like the rest — avoids
    // branchy partial-fill logic for a harmless simplification.
    std::array<std::byte, kKeySizeBytes> bytes_{};
    KeySize size_ = KeySize::Aes256;
    // Counts AesGcm::encrypt() calls made with this key object (advanced via
    // detail::consume_gcm_invocation(), src/internal.hpp). mutable: AesGcm::encrypt() takes `key`
    // by const&, same as every other consumer, but still needs to advance
    // this counter. Relaxed atomics are enough — this is a usage-budget
    // counter, not a synchronization primitive guarding the key bytes
    // themselves.
    mutable std::atomic<std::uint64_t> gcm_invocations_{0};
};

} // namespace aeslib
