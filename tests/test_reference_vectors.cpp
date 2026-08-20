// Cross-checks Aes256Ctr's output against a second, independent AES-256-CTR
// implementation (Python's `cryptography` library, cross-verified against
// the `openssl enc -aes-256-ctr` CLI), rather than only this codebase's own
// FIPS-197 block-cipher KAT. NIST doesn't publish CTR vectors for this
// library's 96-bit-nonce/32-bit-counter split (see DESIGN.md), so these
// vectors were generated locally against that exact construction: the CTR
// input block is `nonce (12 bytes) || counter (4-byte big-endian, starting
// at 0)`, matching make_counter_block() in src/aes256_ctr.cpp.
//
// Reproduction (Python, `pip install cryptography`):
//   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
//   iv = nonce + counter.to_bytes(4, 'big')
//   Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
// Independently reproduced with:
//   openssl enc -aes-256-ctr -e -K <key-hex> -iv <nonce-hex><00000000> \
//     -in plaintext.bin -out ciphertext.bin -nopad

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <vector>

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/container.hpp"
#include "aeslib/key.hpp"
#include "test_support.hpp"

namespace {

using aeslib::Aes256Ctr;
using aeslib::Container;
using aeslib::SecretKey;

std::vector<std::byte> bytes_from_hex(const std::string& hex) {
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

// SecretKey has no public constructor from raw bytes — round-trip through a
// temp file using the same wire format save_to_file() writes (same approach
// as test_aes_core.cpp's key_from_bytes).
SecretKey key_from_hex(const std::string& hex) {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("aeslib_test_refkey_" + std::to_string(++counter) + ".key");
    const auto bytes = bytes_from_hex(hex);
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(1)); // version
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    SecretKey key = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    return key;
}

std::array<std::byte, 12> nonce_from_hex(const std::string& hex) {
    std::array<std::byte, 12> nonce{};
    const auto bytes = bytes_from_hex(hex);
    CHECK(bytes.size() == 12);
    std::copy(bytes.begin(), bytes.end(), nonce.begin());
    return nonce;
}

struct Vector {
    const char* key_hex;
    const char* nonce_hex;
    const char* plaintext_hex;
    const char* ciphertext_hex;
};

// clang-format off
constexpr Vector kVectors[] = {
    // Single block.
    {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "f28122856e1cf9a7216a30d111f3997f",
    },
    // Eight full blocks (exercises the counter incrementing past 0).
    {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6a7a8a9aaab",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "b7a537cd414165b068d588c3344b841e4c788436bb5e85b7e03b10317d04dbc"
        "fc6395e0e61ee24984a4cadf82b57eef1409d6b23a682745ba4371cbd43964b3e",
    },
    // 13-byte plaintext: exercises the partial-final-block path.
    {
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        "e0e1e2e3e4e5e6e7e8e9eaeb",
        "48656c6c6f2c20776f726c6421",
        "9338233e44dd1178d6a29ead0c",
    },
};
// clang-format on

} // namespace

AESLIB_TEST(reference_vectors, encrypt_matches_independent_implementation) {
    for (const auto& v : kVectors) {
        const SecretKey key = key_from_hex(v.key_hex);
        const auto nonce = nonce_from_hex(v.nonce_hex);
        const auto plaintext = bytes_from_hex(v.plaintext_hex);
        const auto expected_ciphertext = bytes_from_hex(v.ciphertext_hex);

        // Aes256Ctr::decrypt() applies the same keystream-XOR transform as
        // encrypt() but takes an explicit nonce instead of generating a
        // random one, so it doubles as a deterministic "encrypt with this
        // fixed nonce" for comparing against the precomputed reference.
        const auto computed_ciphertext = Aes256Ctr::decrypt(key, Container{nonce, plaintext});
        CHECK_EQ(computed_ciphertext, expected_ciphertext);

        // And the reverse: decrypting the reference ciphertext must recover
        // the original plaintext.
        const auto decrypted = Aes256Ctr::decrypt(key, Container{nonce, expected_ciphertext});
        CHECK_EQ(decrypted, plaintext);
    }
}
