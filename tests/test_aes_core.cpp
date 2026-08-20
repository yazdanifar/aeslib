// Validates both AES-256 block-cipher backends against the FIPS-197
// Appendix C.3 known-answer test, and against each other, independent of
// whatever architecture happens to be running the test binary.

#include <filesystem>
#include <fstream>
#include <string>

#include "aeslib/key.hpp"
#include "src/internal.hpp"
#include "test_support.hpp"

namespace {

using aeslib::SecretKey;
using aeslib::detail::Block;

// FIPS-197 Appendix C.3: AES-256 encryption of a single block.
constexpr unsigned char kKatKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
constexpr unsigned char kKatPlaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
constexpr unsigned char kKatCiphertext[16] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
};

// SecretKey has no public constructor from raw bytes (deliberately, see
// key.hpp) — round-trip through a temp file the same way a real caller
// would, using the same wire format save_to_file() writes.
SecretKey key_from_bytes(const unsigned char (&bytes)[32]) {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("aeslib_test_key_" + std::to_string(++counter) + ".key");
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(1)); // version
        out.write(reinterpret_cast<const char*>(bytes), 32);
    }
    SecretKey key = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    return key;
}

Block block_from_bytes(const unsigned char (&bytes)[16]) {
    Block block{};
    for (int i = 0; i < 16; ++i) block[static_cast<std::size_t>(i)] = static_cast<std::byte>(bytes[i]);
    return block;
}

} // namespace

AESLIB_TEST(aes_core, software_matches_fips197_kat) {
    const SecretKey key = key_from_bytes(kKatKey);
    const Block plaintext = block_from_bytes(kKatPlaintext);
    const Block expected = block_from_bytes(kKatCiphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, hardware_matches_fips197_kat_when_available) {
    if (!aeslib::cpu::has_aes_ni()) {
        std::printf("   (skipped: no AES-NI on this machine)\n");
        return;
    }
    const SecretKey key = key_from_bytes(kKatKey);
    const Block plaintext = block_from_bytes(kKatPlaintext);
    const Block expected = block_from_bytes(kKatCiphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_ni(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, backends_agree_on_random_blocks) {
    if (!aeslib::cpu::has_aes_ni()) {
        std::printf("   (skipped: no AES-NI on this machine)\n");
        return;
    }
    for (int trial = 0; trial < 8; ++trial) {
        unsigned char key_bytes[32];
        unsigned char block_bytes[16];
        aeslib::rng::fill_random(reinterpret_cast<std::byte*>(key_bytes), sizeof(key_bytes));
        aeslib::rng::fill_random(reinterpret_cast<std::byte*>(block_bytes), sizeof(block_bytes));

        const SecretKey key = key_from_bytes(key_bytes);
        const Block block = block_from_bytes(block_bytes);

        const Block soft_result = aeslib::detail::aes256_encrypt_block_soft(key, block);
        const Block ni_result = aeslib::detail::aes256_encrypt_block_ni(key, block);
        CHECK(soft_result == ni_result);
    }
}
