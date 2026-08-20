#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace aeslib {

// On-disk container for encrypted data. Deliberately does NOT hold the key —
// key and ciphertext are always stored in separate files (see SecretKey).
//
// Wire format (all integers little-endian):
//   bytes 0..3   magic      "AESC"
//   byte  4      version    currently kContainerVersion
//   bytes 5..16  nonce      12 bytes, the CTR nonce (see Aes256Ctr)
//   bytes 17..24 ct_len     uint64_t, ciphertext length in bytes
//   bytes 25..   ciphertext ct_len bytes
//
// The version byte lets a future format change (e.g. a different nonce
// size, or an AEAD tag) be introduced without breaking readers of old files:
// a reader can dispatch on version before parsing the rest.
inline constexpr std::size_t kNonceSizeBytes = 12;
inline constexpr std::uint8_t kContainerVersion = 1;

struct Container {
    std::array<std::byte, kNonceSizeBytes> nonce{};
    std::vector<std::byte> ciphertext;
};

// Serializes a container to bytes using the wire format documented above.
std::vector<std::byte> serialize(const Container& container);

// Parses bytes previously produced by serialize(). Throws FormatError on a
// bad magic, unsupported version, or truncated input.
Container deserialize(const std::vector<std::byte>& data);

// Convenience file I/O built on serialize/deserialize plus plain file reads.
void save_container(const Container& container, const std::filesystem::path& path);
Container load_container(const std::filesystem::path& path);

std::vector<std::byte> read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data);

} // namespace aeslib
