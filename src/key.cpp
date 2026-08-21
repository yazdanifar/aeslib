#include "aeslib/key.hpp"

#include <algorithm>
#include <cstdint>

#include "aeslib/exceptions.hpp"
#include "internal.hpp"

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace aeslib {

namespace {
// Version 2: version(1) || size_marker(1, = 16 or 32) || size_marker bytes
// of key. Version 1 (no size marker, always 32 raw key bytes) is no longer
// accepted — no real persisted files exist outside this repo's own tests, so
// this is a clean break, not a compat shim.
constexpr std::uint8_t kKeyFileVersion = 2;
}

SecretKey::SecretKey() { lock_memory(); }

SecretKey SecretKey::generate() { return generate(KeySize::Aes256); }

SecretKey SecretKey::generate(KeySize size) {
    SecretKey key;
    key.size_ = size;
    // Always fill the full 32-byte capacity regardless of logical size (see
    // bytes_'s comment in key.hpp) — no branchy partial-fill logic.
    rng::fill_random(key.bytes_.data(), key.bytes_.size());
    return key;
}

KeySize SecretKey::size() const noexcept { return size_; }

std::size_t SecretKey::size_bytes() const noexcept { return static_cast<std::size_t>(size_); }

SecretKey::SecretKey(SecretKey&& other) noexcept
    : bytes_(other.bytes_), gcm_invocations_(other.gcm_invocations_.load(std::memory_order_relaxed)) {
    lock_memory();
    other.wipe();
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept {
    if (this != &other) {
        wipe();
        bytes_ = other.bytes_;
        gcm_invocations_.store(other.gcm_invocations_.load(std::memory_order_relaxed), std::memory_order_relaxed);
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
    const std::size_t key_len = size_bytes();
#if defined(_WIN32)
    // CreateFile/WriteFile instead of std::ofstream: an iostream sink copies
    // through its own internal streambuf on the way to the OS, which is
    // exactly the kind of incidental, unwiped key-byte copy this bonus asks
    // to avoid. The raw Win32 API writes straight from bytes_ with no
    // intermediate buffer.
    // FILE_FLAG_OPEN_REPARSEPOINT + the reparse-point check right below stop
    // CreateFileW from transparently following a symlink/junction an
    // attacker planted at `path` ahead of time — without it, the key bytes
    // below would get written wherever that reparse point points, with this
    // process's permissions (a classic TOCTOU file-clobber primitive).
    HANDLE h = ::CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSEPOINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw IoError("failed to create key file: " + path.string());
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (::GetFileInformationByHandle(h, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        ::CloseHandle(h);
        throw IoError("refusing to write key file through a symlink/reparse point: " + path.string());
    }
    const char version = static_cast<char>(kKeyFileVersion);
    const char size_marker = static_cast<char>(key_len);
    DWORD written = 0;
    const bool ok = ::WriteFile(h, &version, 1, &written, nullptr) && written == 1 &&
                     ::WriteFile(h, &size_marker, 1, &written, nullptr) && written == 1 &&
                     ::WriteFile(h, bytes_.data(), static_cast<DWORD>(key_len), &written, nullptr) &&
                     written == key_len;
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
    // O_NOFOLLOW closes the same symlink-planting TOCTOU as the Windows
    // branch's reparse-point check above: open() fails with ELOOP instead of
    // transparently following a symlink an attacker planted at `path`.
    int fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        throw IoError("failed to create key file: " + path.string());
    }
    const char header[2] = {static_cast<char>(kKeyFileVersion), static_cast<char>(key_len)};
    bool ok = ::write(fd, header, sizeof(header)) == static_cast<ssize_t>(sizeof(header));
    if (ok) {
        const auto* data = reinterpret_cast<const char*>(bytes_.data());
        std::size_t written = 0;
        while (written < key_len) {
            const ssize_t n = ::write(fd, data + written, key_len - written);
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

namespace {
bool is_valid_size_marker(std::uint8_t marker) {
    return marker == static_cast<std::uint8_t>(KeySize::Aes128) || marker == static_cast<std::uint8_t>(KeySize::Aes256);
}
} // namespace

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
    char header[2] = {0, 0};
    DWORD read = 0;
    const bool got_header = ::ReadFile(h, header, 2, &read, nullptr) && read == 2;
    const auto version = static_cast<std::uint8_t>(header[0]);
    const auto size_marker = static_cast<std::uint8_t>(header[1]);
    if (!got_header || version != kKeyFileVersion || !is_valid_size_marker(size_marker)) {
        ::CloseHandle(h);
        throw FormatError("unsupported or corrupt key file: " + path.string());
    }

    SecretKey key;
    key.size_ = static_cast<KeySize>(size_marker);
    const bool ok = ::ReadFile(h, key.bytes_.data(), static_cast<DWORD>(size_marker), &read, nullptr) &&
                     read == size_marker;
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
    char header[2] = {0, 0};
    const bool got_header = ::read(fd, header, sizeof(header)) == static_cast<ssize_t>(sizeof(header));
    const auto version = static_cast<std::uint8_t>(header[0]);
    const auto size_marker = static_cast<std::uint8_t>(header[1]);
    if (!got_header || version != kKeyFileVersion || !is_valid_size_marker(size_marker)) {
        ::close(fd);
        throw FormatError("unsupported or corrupt key file: " + path.string());
    }

    SecretKey key;
    key.size_ = static_cast<KeySize>(size_marker);
    auto* data = reinterpret_cast<char*>(key.bytes_.data());
    std::size_t total_read = 0;
    bool ok = true;
    while (ok && total_read < size_marker) {
        const ssize_t n = ::read(fd, data + total_read, size_marker - total_read);
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

SecretKey key_from_bytes(const std::byte* bytes, KeySize size) {
    SecretKey key;
    key.size_ = size;
    std::copy_n(bytes, static_cast<std::size_t>(size), key.bytes_.begin());
    return key;
}

std::uint64_t consume_gcm_invocation(const SecretKey& key) noexcept {
    return key.gcm_invocations_.fetch_add(1, std::memory_order_relaxed);
}
} // namespace detail

} // namespace aeslib
