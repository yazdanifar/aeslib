#pragma once

#include <array>
#include <cstddef>
#include <filesystem>

namespace aeslib {

inline constexpr std::size_t kKeySizeBytes = 32; // AES-256

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

    // Loads a key previously written by save(). File format: 1-byte version
    // marker followed by kKeySizeBytes raw key bytes.
    [[nodiscard]] static SecretKey load_from_file(const std::filesystem::path& path);

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;
    ~SecretKey();

    // Writes the key to its own file, separate from any ciphertext. On
    // POSIX the file is created with 0600 permissions before any key bytes
    // are written.
    void save_to_file(const std::filesystem::path& path) const;

private:
    friend const std::array<std::byte, kKeySizeBytes>& detail::key_bytes(const SecretKey&) noexcept;

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

    std::array<std::byte, kKeySizeBytes> bytes_{};
};

} // namespace aeslib
