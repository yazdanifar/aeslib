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
// The sole raw-byte access path for a SecretKey. Deliberately not a public
// SecretKey member: an ordinary caller of this library has no need to see
// raw key bytes at all (aes256_ctr.cpp only ever passes SecretKey by const&
// down to the backends), so nothing invites `auto leaked = key.bytes();` or
// `std::cout << key.bytes()[0];` — the kind of accidental copy/log that
// escapes wipe()/mlock() entirely. This is reachable only from the two AES
// backends' key-expansion code and from tests, both of which reach it the
// same way tests already reach `ct_sbox` — via this internal-only header.
// The one sanctioned way for a caller to get key material out of a
// SecretKey remains the explicit, deliberately-named save_to_file().
const std::array<std::byte, kKeySizeBytes>& key_bytes(const SecretKey& key) noexcept;

// Constructs a SecretKey directly from raw bytes rather than CSPRNG
// generation or file loading — used by cpu_detect.cpp's hardware
// self-verification (which needs to encrypt a fixed FIPS-197 KAT vector, not
// a randomly generated key) and by tests, the same restricted-audience
// pattern as key_bytes() above. `bytes` must point to at least
// static_cast<std::size_t>(size) readable bytes; only that many are copied,
// matching load_from_file()'s behavior (unused capacity for a 16-byte
// AES-128 key stays zero-filled).
SecretKey key_from_bytes(const std::byte* bytes, KeySize size);

// Atomically increments `key`'s AES-GCM invocation counter and returns the
// count *before* this increment (i.e. how many prior AesGcm::encrypt() calls
// have already consumed a fresh random nonce under this key object). Used by
// AesGcm::encrypt() (aes_gcm.cpp) to enforce NIST SP 800-38D §8.3's
// recommended per-key limit on random-nonce GCM encryptions — see DESIGN.md's
// "GCM's per-key usage limit is tighter than the raw birthday bound". The
// count lives on the SecretKey object itself (moved along with it, reset by
// neither copy — which is disabled — nor by reloading the same key bytes
// from disk into a new SecretKey instance), so it bounds usage within one
// object's lifetime, not across process restarts; see DESIGN.md for why that
// gap is accepted rather than closed with persisted state.
std::uint64_t consume_gcm_invocation(const SecretKey& key) noexcept;
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
    friend const std::array<std::byte, kKeySizeBytes>& detail::key_bytes(const SecretKey&) noexcept;
    friend std::uint64_t detail::consume_gcm_invocation(const SecretKey&) noexcept;
    friend SecretKey detail::key_from_bytes(const std::byte*, KeySize);

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
    // Counts AesGcm::encrypt() calls made with this key object (see
    // consume_gcm_invocation above). mutable: AesGcm::encrypt() takes `key`
    // by const&, same as every other consumer, but still needs to advance
    // this counter. Relaxed atomics are enough — this is a usage-budget
    // counter, not a synchronization primitive guarding the key bytes
    // themselves.
    mutable std::atomic<std::uint64_t> gcm_invocations_{0};
};

} // namespace aeslib
