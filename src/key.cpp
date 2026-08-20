#include "aeslib/key.hpp"

#include <cstdint>

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
#if defined(__linux__)
    // mlock() alone says nothing about core dumps: a SIGSEGV/SIGABRT-triggered
    // core still includes locked pages by default. MADV_DONTDUMP is the
    // separate, Linux-specific opt-out for that (glibc/musl both expose it;
    // BSD/macOS have no equivalent, so this is Linux-only). Best-effort, same
    // as mlock() above.
    ::madvise(bytes_.data(), bytes_.size(), MADV_DONTDUMP);
#endif
#endif
}

void SecretKey::unlock_memory() noexcept {
#if defined(_WIN32)
    ::VirtualUnlock(bytes_.data(), static_cast<SIZE_T>(bytes_.size()));
#else
#if defined(__linux__)
    ::madvise(bytes_.data(), bytes_.size(), MADV_DODUMP);
#endif
    ::munlock(bytes_.data(), bytes_.size());
#endif
}

void SecretKey::save_to_file(const std::filesystem::path& path) const {
#if defined(_WIN32)
    // CreateFile/WriteFile instead of std::ofstream: an iostream sink copies
    // through its own internal streambuf on the way to the OS, which is
    // exactly the kind of incidental, unwiped key-byte copy this bonus asks
    // to avoid. The raw Win32 API writes straight from bytes_ with no
    // intermediate buffer.
    HANDLE h = ::CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw IoError("failed to create key file: " + path.string());
    }
    const char version = static_cast<char>(kKeyFileVersion);
    DWORD written = 0;
    const bool ok = ::WriteFile(h, &version, 1, &written, nullptr) && written == 1 &&
                     ::WriteFile(h, bytes_.data(), static_cast<DWORD>(bytes_.size()), &written, nullptr) &&
                     written == bytes_.size();
    ::CloseHandle(h);
    if (!ok) {
        throw IoError("failed to write key file: " + path.string());
    }
#else
    // Create with 0600 permissions from the start (umask alone can't be
    // trusted to exclude group/other), rather than chmod-ing after the fact,
    // and write through the same fd with raw ::write() rather than
    // std::ofstream: an iostream sink copies key bytes through its own
    // internal streambuf on the way to the OS, an incidental unwiped copy
    // this bonus asks to avoid.
    int fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        throw IoError("failed to create key file: " + path.string());
    }
    const char version = static_cast<char>(kKeyFileVersion);
    bool ok = ::write(fd, &version, 1) == 1;
    if (ok) {
        const auto* data = reinterpret_cast<const char*>(bytes_.data());
        std::size_t written = 0;
        while (written < bytes_.size()) {
            const ssize_t n = ::write(fd, data + written, bytes_.size() - written);
            if (n < 0) {
                ok = false;
                break;
            }
            written += static_cast<std::size_t>(n);
        }
    }
    ::close(fd);
    if (!ok) {
        throw IoError("failed to write key file: " + path.string());
    }
#endif
}

SecretKey SecretKey::load_from_file(const std::filesystem::path& path) {
    // Same rationale as save_to_file(): raw OS reads straight into
    // key.bytes_, not through an iostream's internal streambuf, so the key
    // never sits in an extra, unwiped buffer on its way into the SecretKey.
#if defined(_WIN32)
    HANDLE h = ::CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw IoError("failed to open key file: " + path.string());
    }
    char version = 0;
    DWORD read = 0;
    const bool got_version = ::ReadFile(h, &version, 1, &read, nullptr) && read == 1;
    if (!got_version || static_cast<std::uint8_t>(version) != kKeyFileVersion) {
        ::CloseHandle(h);
        throw FormatError("unsupported or corrupt key file: " + path.string());
    }

    SecretKey key;
    const bool ok = ::ReadFile(h, key.bytes_.data(), static_cast<DWORD>(key.bytes_.size()), &read, nullptr) &&
                     read == key.bytes_.size();
    ::CloseHandle(h);
    if (!ok) {
        throw FormatError("key file truncated: " + path.string());
    }
    return key;
#else
    int fd = ::open(path.string().c_str(), O_RDONLY);
    if (fd < 0) {
        throw IoError("failed to open key file: " + path.string());
    }
    char version = 0;
    const bool got_version = ::read(fd, &version, 1) == 1;
    if (!got_version || static_cast<std::uint8_t>(version) != kKeyFileVersion) {
        ::close(fd);
        throw FormatError("unsupported or corrupt key file: " + path.string());
    }

    SecretKey key;
    auto* data = reinterpret_cast<char*>(key.bytes_.data());
    std::size_t total_read = 0;
    bool ok = true;
    while (ok && total_read < key.bytes_.size()) {
        const ssize_t n = ::read(fd, data + total_read, key.bytes_.size() - total_read);
        if (n <= 0) { // 0 == EOF (truncated file), <0 == error
            ok = false;
            break;
        }
        total_read += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (!ok) {
        throw FormatError("key file truncated: " + path.string());
    }
    return key;
#endif
}

namespace detail {
const std::array<std::byte, kKeySizeBytes>& key_bytes(const SecretKey& key) noexcept { return key.bytes_; }
} // namespace detail

} // namespace aeslib
