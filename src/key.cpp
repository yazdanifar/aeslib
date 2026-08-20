#include "aeslib/key.hpp"

#include <cstdint>
#include <fstream>

#include "aeslib/exceptions.hpp"
#include "internal.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace aeslib {

namespace {
constexpr std::uint8_t kKeyFileVersion = 1;
}

SecretKey::SecretKey() { lock_memory(); }

SecretKey SecretKey::generate() {
    SecretKey key;
    rng::fill_random(key.bytes_.data(), key.bytes_.size());
    return key;
}

SecretKey::SecretKey(SecretKey&& other) noexcept : bytes_(other.bytes_) {
    lock_memory();
    other.wipe();
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept {
    if (this != &other) {
        wipe();
        bytes_ = other.bytes_;
        lock_memory();
        other.wipe();
    }
    return *this;
}

SecretKey::~SecretKey() { wipe(); }

void SecretKey::wipe() noexcept {
    // A plain loop can be optimized away by the compiler as a "dead store"
    // since bytes_ is about to go out of scope; volatile prevents that.
    for (volatile std::byte& b : bytes_) b = std::byte{0};
    unlock_memory();
}

void SecretKey::lock_memory() noexcept {
#if defined(_WIN32)
    ::VirtualLock(bytes_.data(), static_cast<SIZE_T>(bytes_.size()));
#else
    ::mlock(bytes_.data(), bytes_.size());
#endif
}

void SecretKey::unlock_memory() noexcept {
#if defined(_WIN32)
    ::VirtualUnlock(bytes_.data(), static_cast<SIZE_T>(bytes_.size()));
#else
    ::munlock(bytes_.data(), bytes_.size());
#endif
}

void SecretKey::save_to_file(const std::filesystem::path& path) const {
#if !defined(_WIN32)
    // Create with 0600 permissions from the start (umask alone can't be
    // trusted to exclude group/other), rather than chmod-ing after the fact.
    int fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        throw IoError("failed to create key file: " + path.string());
    }
    ::close(fd);
#endif

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw IoError("failed to open key file for writing: " + path.string());
    }
    out.put(static_cast<char>(kKeyFileVersion));
    out.write(reinterpret_cast<const char*>(bytes_.data()), static_cast<std::streamsize>(bytes_.size()));
    if (!out) {
        throw IoError("failed to write key file: " + path.string());
    }
}

SecretKey SecretKey::load_from_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw IoError("failed to open key file: " + path.string());
    }

    char version = 0;
    in.get(version);
    if (!in || static_cast<std::uint8_t>(version) != kKeyFileVersion) {
        throw FormatError("unsupported or corrupt key file: " + path.string());
    }

    SecretKey key;
    in.read(reinterpret_cast<char*>(key.bytes_.data()), static_cast<std::streamsize>(key.bytes_.size()));
    if (!in) {
        throw FormatError("key file truncated: " + path.string());
    }
    return key;
}

} // namespace aeslib
