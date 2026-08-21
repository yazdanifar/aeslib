#include "aeslib/container.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "aeslib/exceptions.hpp"

namespace aeslib {

namespace {
constexpr char kMagic[4] = {'A', 'E', 'S', 'C'};
constexpr std::size_t kHeaderSize = 4 + 1 + kNonceSizeBytes + 8; // magic+version+nonce+ct_len
}

std::vector<std::byte> serialize(const Container& container) {
    std::vector<std::byte> out;
    out.reserve(kHeaderSize + container.ciphertext.size());

    for (char c : kMagic) out.push_back(static_cast<std::byte>(c));
    out.push_back(static_cast<std::byte>(kContainerVersion));
    out.insert(out.end(), container.nonce.begin(), container.nonce.end());

    std::uint64_t ct_len = container.ciphertext.size();
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::byte>((ct_len >> (8 * i)) & 0xff));
    }

    out.insert(out.end(), container.ciphertext.begin(), container.ciphertext.end());
    return out;
}

Container deserialize(const std::vector<std::byte>& data) {
    if (data.size() < kHeaderSize) {
        throw FormatError("container truncated: missing header");
    }

    for (std::size_t i = 0; i < 4; ++i) {
        if (static_cast<char>(data[i]) != kMagic[i]) {
            throw FormatError("container has bad magic bytes");
        }
    }

    auto version = static_cast<std::uint8_t>(data[4]);
    if (version != kContainerVersion) {
        throw FormatError("unsupported container version: " + std::to_string(version));
    }

    Container container;
    std::copy_n(data.begin() + 5, kNonceSizeBytes, container.nonce.begin());

    std::uint64_t ct_len = 0;
    for (int i = 0; i < 8; ++i) {
        ct_len |= static_cast<std::uint64_t>(data[5 + kNonceSizeBytes + static_cast<std::size_t>(i)]) << (8 * i);
    }

    if (data.size() - kHeaderSize != ct_len) {
        throw FormatError("container ciphertext length mismatch");
    }

    container.ciphertext.assign(data.begin() + static_cast<std::ptrdiff_t>(kHeaderSize), data.end());
    return container;
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        throw IoError("failed to open file: " + path.string());
    }
    auto size = in.tellg();
    if (size < 0) {
        throw IoError("failed to determine file size: " + path.string());
    }
    in.seekg(0);

    std::vector<std::byte> data(static_cast<std::size_t>(size));
    if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()), size)) {
        throw IoError("failed to read file: " + path.string());
    }
    return data;
}

#if defined(_WIN32)

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data) {
    // FILE_FLAG_OPEN_REPARSEPOINT + the reparse-point check right below stop
    // CreateFileW from transparently following a symlink/junction an
    // attacker planted at `path` ahead of time — without it, this data would
    // get written wherever that reparse point points, with this process's
    // permissions (a classic TOCTOU file-clobber primitive). Same protection
    // as key.cpp's save_to_file.
    HANDLE h = ::CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSEPOINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw IoError("failed to open file for writing: " + path.string());
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (::GetFileInformationByHandle(h, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        ::CloseHandle(h);
        throw IoError("refusing to write through a symlink/reparse point: " + path.string());
    }
    DWORD written = 0;
    const bool ok = data.empty() ||
                     (::WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
                      written == data.size());
    ::CloseHandle(h);
    if (!ok) {
        throw IoError("failed to write file: " + path.string());
    }
}

#else

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data) {
    // O_NOFOLLOW closes the same symlink-planting TOCTOU as the Windows
    // branch's reparse-point check above: open() fails with ELOOP instead of
    // transparently following a symlink an attacker planted at `path`.
    int fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        throw IoError("failed to open file for writing: " + path.string());
    }
    bool ok = true;
    const auto* data_ptr = reinterpret_cast<const char*>(data.data());
    std::size_t written = 0;
    while (ok && written < data.size()) {
        const ssize_t n = ::write(fd, data_ptr + written, data.size() - written);
        if (n < 0) {
            ok = false;
            break;
        }
        written += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (!ok) {
        throw IoError("failed to write file: " + path.string());
    }
}

#endif

void save_container(const Container& container, const std::filesystem::path& path) {
    write_file(path, serialize(container));
}

Container load_container(const std::filesystem::path& path) { return deserialize(read_file(path)); }

} // namespace aeslib
