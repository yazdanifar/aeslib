#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>

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

// Parses a lowercase hex string into raw bytes, for known-answer test
// vectors. A helper rather than hand-transcribed std::byte literals: an
// earlier draft of these tests hand-typed byte arrays and got indices
// wrong, so vectors are kept in their canonical hex form (copy-pasteable
// straight from the RFC/FIPS text) and parsed here instead.
std::vector<std::byte> hex_to_bytes(std::string_view hex) {
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        return static_cast<std::uint8_t>(c - 'a' + 10);
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

template <std::size_t N>
bool bytes_equal(const std::array<std::byte, N>& actual, const std::vector<std::byte>& expected) {
    return expected.size() == N && std::equal(actual.begin(), actual.end(), expected.begin());
}
} // namespace

// --- Known-answer tests for the from-scratch primitives, sourced from
// official reference material rather than self-generated: SHA-256 (FIPS
// 180-4), HMAC-SHA256 (RFC 4231 test cases 1-2), PBKDF2-HMAC-SHA256 (RFC
// 7914 Appendix A). These matter beyond behavioral round-trip coverage:
// save/load both call the same primitive, so a round-trip test alone
// cannot detect an internally self-consistent but wrong implementation
// (e.g. a transposed round constant) — only comparison against an
// independent reference can.

AESLIB_TEST(key_storage, sha256_fips180_4_empty_string) {
    auto digest = aeslib::detail::sha256(nullptr, 0);
    CHECK(bytes_equal(digest, hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));
}

AESLIB_TEST(key_storage, sha256_fips180_4_abc) {
    const char* msg = "abc";
    auto digest = aeslib::detail::sha256(reinterpret_cast<const std::byte*>(msg), 3);
    CHECK(bytes_equal(digest, hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
}

AESLIB_TEST(key_storage, hmac_sha256_rfc4231_case1) {
    std::vector<std::byte> key(20, std::byte{0x0b});
    std::string_view data = "Hi There";
    auto tag = aeslib::detail::hmac_sha256(key.data(), key.size(),
                                            reinterpret_cast<const std::byte*>(data.data()), data.size());
    CHECK(bytes_equal(tag, hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")));
}

AESLIB_TEST(key_storage, hmac_sha256_rfc4231_case2) {
    std::string_view key = "Jefe";
    std::string_view data = "what do ya want for nothing?";
    auto tag = aeslib::detail::hmac_sha256(reinterpret_cast<const std::byte*>(key.data()), key.size(),
                                            reinterpret_cast<const std::byte*>(data.data()), data.size());
    CHECK(bytes_equal(tag, hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")));
}

AESLIB_TEST(key_storage, pbkdf2_hmac_sha256_rfc7914_c1) {
    const char* salt = "salt";
    auto dk = aeslib::detail::pbkdf2_hmac_sha256("passwd", reinterpret_cast<const std::byte*>(salt), 4, 1);
    CHECK(bytes_equal(dk, hex_to_bytes("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacb"
                                        "c49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a1978"
                                        "3")));
}

AESLIB_TEST(key_storage, pbkdf2_hmac_sha256_rfc7914_c80000) {
    const char* salt = "NaCl";
    auto dk = aeslib::detail::pbkdf2_hmac_sha256("Password", reinterpret_cast<const std::byte*>(salt), 4, 80000);
    CHECK(bytes_equal(dk, hex_to_bytes("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab5"
                                        "6a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8"
                                        "d")));
}


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
