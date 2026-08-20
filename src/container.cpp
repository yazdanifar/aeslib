#include "aeslib/container.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>

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

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw IoError("failed to open file for writing: " + path.string());
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) {
        throw IoError("failed to write file: " + path.string());
    }
}

void save_container(const Container& container, const std::filesystem::path& path) {
    write_file(path, serialize(container));
}

Container load_container(const std::filesystem::path& path) { return deserialize(read_file(path)); }

} // namespace aeslib
