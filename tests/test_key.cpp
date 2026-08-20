#include <filesystem>
#include <fstream>

#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"
#include "test_support.hpp"

namespace {
using aeslib::FormatError;
using aeslib::IoError;
using aeslib::SecretKey;
} // namespace

AESLIB_TEST(key, generate_produces_distinct_keys) {
    const SecretKey a = SecretKey::generate();
    const SecretKey b = SecretKey::generate();
    CHECK(a.bytes() != b.bytes());
}

AESLIB_TEST(key, save_load_round_trip) {
    const SecretKey original = SecretKey::generate();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_roundtrip.key";
    original.save_to_file(path);
    const SecretKey loaded = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    CHECK(loaded.bytes() == original.bytes());
}

AESLIB_TEST(key, load_missing_file_throws_io_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_missing.key";
    CHECK_THROWS(SecretKey::load_from_file(path), IoError);
}

AESLIB_TEST(key, load_bad_version_throws_format_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_bad_version.key";
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(99)); // not kKeyFileVersion
        std::string padding(aeslib::kKeySizeBytes, '\0');
        out.write(padding.data(), static_cast<std::streamsize>(padding.size()));
    }
    CHECK_THROWS(SecretKey::load_from_file(path), FormatError);
    std::filesystem::remove(path);
}

AESLIB_TEST(key, load_truncated_file_throws_format_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_truncated.key";
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(1));
        out.put(static_cast<char>(0)); // only 1 of 32 key bytes present
    }
    CHECK_THROWS(SecretKey::load_from_file(path), FormatError);
    std::filesystem::remove(path);
}
