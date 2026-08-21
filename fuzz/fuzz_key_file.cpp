// libFuzzer harness for SecretKey::load_from_file_encrypted() (aeslib/key.hpp)
// — the richest untrusted-input parser touching key material: magic,
// version, key-size marker, salt, PBKDF2 iteration count, nonce, wrapped
// key, HMAC tag (see src/key_storage.cpp). Unlike the container parsers,
// this one only takes a filesystem path, so each iteration's fuzz bytes are
// written to a per-process temp file first.
//
// Build with -DAESLIB_BUILD_FUZZERS=ON (Clang required). See README.md.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>

#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {
std::filesystem::path fuzz_key_file_path() {
#if defined(_WIN32)
    const auto pid = static_cast<unsigned long>(_getpid());
#else
    const auto pid = static_cast<unsigned long>(::getpid());
#endif
    return std::filesystem::temp_directory_path() / ("aeslib_fuzz_key_" + std::to_string(pid) + ".tmp");
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::filesystem::path path = fuzz_key_file_path();
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    try {
        [[maybe_unused]] auto key = aeslib::SecretKey::load_from_file_encrypted(path, "fuzz-harness-passphrase");
    } catch (const aeslib::FormatError&) {
        // Expected: structurally malformed input correctly rejected.
    } catch (const aeslib::AuthenticationError&) {
        // Expected: HMAC tag doesn't verify against random fuzz bytes.
    }
    return 0;
}
