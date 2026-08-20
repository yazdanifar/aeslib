#pragma once

#include <array>
#include <cstddef>
#include <filesystem>

namespace aeslib {

inline constexpr std::size_t kKeySizeBytes = 32; // AES-256

// Move-only holder for a raw AES-256 key. Copy is disabled so a key can't be
// accidentally duplicated; the backing bytes are wiped on destruction (and on
// move-from) so a key doesn't linger in memory longer than its owner is
// alive.
class SecretKey {
public:
    // Generates a fresh 256-bit key using the platform CSPRNG (see
    // csprng.hpp) — never a general-purpose PRNG.
    static SecretKey generate();

    // Loads a key previously written by save(). File format: 1-byte version
    // marker followed by kKeySizeBytes raw key bytes.
    static SecretKey load_from_file(const std::filesystem::path& path);

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;
    ~SecretKey();

    // Writes the key to its own file, separate from any ciphertext. On
    // POSIX the file is created with 0600 permissions before any key bytes
    // are written.
    void save_to_file(const std::filesystem::path& path) const;

    const std::array<std::byte, kKeySizeBytes>& bytes() const { return bytes_; }

private:
    SecretKey() = default;
    void wipe() noexcept;

    std::array<std::byte, kKeySizeBytes> bytes_{};
};

} // namespace aeslib
