#include <filesystem>

#include "aeslib/container.hpp"
#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"
#include "test_support.hpp"
#include "src/internal.hpp"

namespace {
using aeslib::AuthenticationError;
using aeslib::FormatError;
using aeslib::SecretKey;
using aeslib::read_file;
using aeslib::write_file;
} // namespace


// Round-trip with correct passphrase.
AESLIB_TEST(key_storage, save_load_encrypted_round_trip) {
    const SecretKey original = SecretKey::generate();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_encrypted.key";
    constexpr std::uint32_t fast_iterations = 100;
    original.save_to_file_encrypted(path, "mypassphrase", fast_iterations);
    const SecretKey loaded = SecretKey::load_from_file_encrypted(path, "mypassphrase");
    std::filesystem::remove(path);
    CHECK(aeslib::detail::key_bytes(loaded) == aeslib::detail::key_bytes(original));
}

// Wrong passphrase throws AuthenticationError (all remaining tests use fast iterations for speed).

AESLIB_TEST(key_storage, load_encrypted_wrong_passphrase) {
    const SecretKey original = SecretKey::generate();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_encrypted_wrong_pass.key";
    constexpr std::uint32_t fast_iterations = 1000;
    original.save_to_file_encrypted(path, "correct_passphrase", fast_iterations);
    CHECK_THROWS(SecretKey::load_from_file_encrypted(path, "wrong_passphrase"), AuthenticationError);
    std::filesystem::remove(path);
}

// Tampered ciphertext throws AuthenticationError.
AESLIB_TEST(key_storage, load_encrypted_tampered_ciphertext) {
    const SecretKey original = SecretKey::generate();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_encrypted_tampered.key";
    constexpr std::uint32_t fast_iterations = 1000;
    original.save_to_file_encrypted(path, "mypassphrase", fast_iterations);

    // Read the file, flip a byte in the ciphertext, write it back.
    std::vector<std::byte> file_data = read_file(path);
    if (file_data.size() >= 40) {
        // Flip bit in the ciphertext region (around byte 50).
        file_data[50] ^= std::byte{0x01};
        write_file(path, file_data);
        CHECK_THROWS(SecretKey::load_from_file_encrypted(path, "mypassphrase"), AuthenticationError);
    }
    std::filesystem::remove(path);
}

// Each save produces distinct salt and nonce.
AESLIB_TEST(key_storage, save_encrypted_produces_distinct_salt_and_nonce) {
    const SecretKey key = SecretKey::generate();
    const auto path1 = std::filesystem::temp_directory_path() / "aeslib_test_enc_1.key";
    const auto path2 = std::filesystem::temp_directory_path() / "aeslib_test_enc_2.key";
    constexpr std::uint32_t fast_iterations = 1000;
    key.save_to_file_encrypted(path1, "passphrase", fast_iterations);
    key.save_to_file_encrypted(path2, "passphrase", fast_iterations);
    std::vector<std::byte> file1 = read_file(path1);
    std::vector<std::byte> file2 = read_file(path2);
    // Files should differ (different salt and nonce).
    CHECK(file1 != file2);
    std::filesystem::remove(path1);
    std::filesystem::remove(path2);
}

// Bad magic throws FormatError.
AESLIB_TEST(key_storage, load_encrypted_bad_magic) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_enc_bad_magic.key";
    std::vector<std::byte> bad_file(101);
    bad_file[0] = std::byte{'X'};
    write_file(path, bad_file);
    CHECK_THROWS(SecretKey::load_from_file_encrypted(path, "passphrase"), FormatError);
    std::filesystem::remove(path);
}

// Bad version throws FormatError.
AESLIB_TEST(key_storage, load_encrypted_bad_version) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_enc_bad_version.key";
    std::vector<std::byte> bad_file(101);
    bad_file[0] = std::byte{'A'};
    bad_file[1] = std::byte{'E'};
    bad_file[2] = std::byte{'S'};
    bad_file[3] = std::byte{'W'};
    bad_file[4] = std::byte{99}; // Bad version, not 1.
    write_file(path, bad_file);
    CHECK_THROWS(SecretKey::load_from_file_encrypted(path, "passphrase"), FormatError);
    std::filesystem::remove(path);
}

// Truncated file throws FormatError.
AESLIB_TEST(key_storage, load_encrypted_truncated) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_enc_truncated.key";
    std::vector<std::byte> truncated(50); // Too short.
    write_file(path, truncated);
    CHECK_THROWS(SecretKey::load_from_file_encrypted(path, "passphrase"), FormatError);
    std::filesystem::remove(path);
}
