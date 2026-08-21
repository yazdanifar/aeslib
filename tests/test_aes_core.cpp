// Validates both AES-256 block-cipher backends against the FIPS-197
// Appendix C.3 known-answer test, and against each other, independent of
// whatever architecture happens to be running the test binary.

#include <filesystem>
#include <fstream>
#include <string>

#include "aeslib/key.hpp"
#include "src/aes_key_schedule.hpp"
#include "src/internal.hpp"
#include "src/kat_vector.hpp"
#include "test_support.hpp"

namespace {

using aeslib::SecretKey;
using aeslib::detail::Block;

// FIPS-197 Appendix C.3: AES-256 encryption of a single block. Shared with
// cpu_detect.cpp's hardware self-verification via src/kat_vector.hpp.
using aeslib::detail::kKat256Ciphertext;
using aeslib::detail::kKat256Key;
using aeslib::detail::kKat256Plaintext;
constexpr const unsigned char (&kKatKey)[32] = kKat256Key;
constexpr const unsigned char (&kKatPlaintext)[16] = kKat256Plaintext;
constexpr const unsigned char (&kKatCiphertext)[16] = kKat256Ciphertext;

// SecretKey has no public constructor from raw bytes (deliberately, see
// key.hpp) — round-trip through a temp file the same way a real caller
// would, using the same wire format save_to_file() writes (version 2:
// version || size_marker || size_marker bytes of key).
SecretKey key_from_bytes(const unsigned char (&bytes)[32]) {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("aeslib_test_key_" + std::to_string(++counter) + ".key");
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(2)); // version
        out.put(static_cast<char>(32)); // size marker
        out.write(reinterpret_cast<const char*>(bytes), 32);
    }
    SecretKey key = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    return key;
}

SecretKey key_from_bytes16(const unsigned char (&bytes)[16]) {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("aeslib_test_key128_" + std::to_string(++counter) + ".key");
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(2)); // version
        out.put(static_cast<char>(16)); // size marker
        out.write(reinterpret_cast<const char*>(bytes), 16);
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

// Canonical AES S-box (FIPS-197 Fig. 7), kept here as test-only data purely
// to verify the constant-time GF(2^8)-inversion implementation in
// src/aes_core_soft.cpp against every possible input — it is deliberately
// NOT present anywhere in production code, which no longer contains any
// table indexed by secret data.
// clang-format off
constexpr std::array<unsigned char, 256> kCanonicalSBox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
// clang-format on

// A second, independent AES-256 ECB known-answer test (NIST CAVP
// AES256KeySbox-style single-block vector), on top of FIPS-197 C.3 above, for
// broader round-transform coverage.
constexpr unsigned char kKat2Key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
constexpr unsigned char kKat2Plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};
constexpr unsigned char kKat2Ciphertext[16] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
};

} // namespace

AESLIB_TEST(aes_core, software_matches_fips197_kat) {
    const SecretKey key = key_from_bytes(kKatKey);
    const Block plaintext = block_from_bytes(kKatPlaintext);
    const Block expected = block_from_bytes(kKatCiphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, software_matches_second_kat) {
    // NIST SP 800-38A F.1.5's AES-256 example key/plaintext, ECB single block.
    const SecretKey key = key_from_bytes(kKat2Key);
    const Block plaintext = block_from_bytes(kKat2Plaintext);
    const Block expected = block_from_bytes(kKat2Ciphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, expand_key_matches_fips197_appendix_a3) {
    // FIPS-197 Appendix A.3: the full 60-word (15-round-key) AES-256 key
    // schedule for the same key as kKat2Key above, checked word-for-word.
    // This template is now shared by both the software and ARM Crypto
    // Extensions backends (see src/aes_key_schedule.hpp), so a schedule bug
    // here would otherwise only surface indirectly, through both backends'
    // block-level KATs failing identically.
    // clang-format off
    constexpr std::array<std::array<unsigned char, 4>, 60> kExpectedWords = {{
        {0x60,0x3d,0xeb,0x10}, {0x15,0xca,0x71,0xbe}, {0x2b,0x73,0xae,0xf0}, {0x85,0x7d,0x77,0x81},
        {0x1f,0x35,0x2c,0x07}, {0x3b,0x61,0x08,0xd7}, {0x2d,0x98,0x10,0xa3}, {0x09,0x14,0xdf,0xf4},
        {0x9b,0xa3,0x54,0x11}, {0x8e,0x69,0x25,0xaf}, {0xa5,0x1a,0x8b,0x5f}, {0x20,0x67,0xfc,0xde},
        {0xa8,0xb0,0x9c,0x1a}, {0x93,0xd1,0x94,0xcd}, {0xbe,0x49,0x84,0x6e}, {0xb7,0x5d,0x5b,0x9a},
        {0xd5,0x9a,0xec,0xb8}, {0x5b,0xf3,0xc9,0x17}, {0xfe,0xe9,0x42,0x48}, {0xde,0x8e,0xbe,0x96},
        {0xb5,0xa9,0x32,0x8a}, {0x26,0x78,0xa6,0x47}, {0x98,0x31,0x22,0x29}, {0x2f,0x6c,0x79,0xb3},
        {0x81,0x2c,0x81,0xad}, {0xda,0xdf,0x48,0xba}, {0x24,0x36,0x0a,0xf2}, {0xfa,0xb8,0xb4,0x64},
        {0x98,0xc5,0xbf,0xc9}, {0xbe,0xbd,0x19,0x8e}, {0x26,0x8c,0x3b,0xa7}, {0x09,0xe0,0x42,0x14},
        {0x68,0x00,0x7b,0xac}, {0xb2,0xdf,0x33,0x16}, {0x96,0xe9,0x39,0xe4}, {0x6c,0x51,0x8d,0x80},
        {0xc8,0x14,0xe2,0x04}, {0x76,0xa9,0xfb,0x8a}, {0x50,0x25,0xc0,0x2d}, {0x59,0xc5,0x82,0x39},
        {0xde,0x13,0x69,0x67}, {0x6c,0xcc,0x5a,0x71}, {0xfa,0x25,0x63,0x95}, {0x96,0x74,0xee,0x15},
        {0x58,0x86,0xca,0x5d}, {0x2e,0x2f,0x31,0xd7}, {0x7e,0x0a,0xf1,0xfa}, {0x27,0xcf,0x73,0xc3},
        {0x74,0x9c,0x47,0xab}, {0x18,0x50,0x1d,0xda}, {0xe2,0x75,0x7e,0x4f}, {0x74,0x01,0x90,0x5a},
        {0xca,0xfa,0xaa,0xe3}, {0xe4,0xd5,0x9b,0x34}, {0x9a,0xdf,0x6a,0xce}, {0xbd,0x10,0x19,0x0d},
        {0xfe,0x48,0x90,0xd1}, {0xe6,0x18,0x8d,0x0b}, {0x04,0x6d,0xf3,0x44}, {0x70,0x6c,0x63,0x1e},
    }};
    // clang-format on

    const SecretKey key = key_from_bytes(kKat2Key);
    const auto schedule = aeslib::detail::expand_key<8, 14>(key);
    for (std::size_t i = 0; i < kExpectedWords.size(); ++i) {
        for (int b = 0; b < 4; ++b) {
            CHECK_EQ(static_cast<unsigned>(schedule[i][static_cast<std::size_t>(b)]),
                     static_cast<unsigned>(kExpectedWords[i][static_cast<std::size_t>(b)]));
        }
    }
}

AESLIB_TEST(aes_core, ct_sbox_matches_canonical_table_exhaustively) {
    // Verifies the constant-time GF(2^8)-inversion S-box (src/aes_core_soft.cpp)
    // against the textbook table for every possible byte, not just the values
    // that happen to appear in the KAT vectors above.
    for (int x = 0; x < 256; ++x) {
        const auto input = static_cast<unsigned char>(x);
        CHECK_EQ(static_cast<unsigned>(aeslib::detail::ct_sbox(input)), static_cast<unsigned>(kCanonicalSBox[static_cast<std::size_t>(x)]));
    }
}

AESLIB_TEST(aes_core, hardware_matches_fips197_kat_when_available) {
    if (!aeslib::cpu::has_hw_aes()) {
        std::printf("   (skipped: no hardware AES acceleration on this machine)\n");
        return;
    }
    const SecretKey key = key_from_bytes(kKatKey);
    const Block plaintext = block_from_bytes(kKatPlaintext);
    const Block expected = block_from_bytes(kKatCiphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_hw(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, backends_agree_on_random_blocks) {
    if (!aeslib::cpu::has_hw_aes()) {
        std::printf("   (skipped: no hardware AES acceleration on this machine)\n");
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
        const Block hw_result = aeslib::detail::aes256_encrypt_block_hw(key, block);
        CHECK(soft_result == hw_result);
    }
}

AESLIB_TEST(aes_core, third_kat_vector_nist_cavp) {
    // Additional NIST CAVP AES-256 vector for broader coverage.
    // This vector is from NIST's official test vectors.
    constexpr unsigned char kKat3Key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    constexpr unsigned char kKat3Plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    constexpr unsigned char kKat3Ciphertext[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
    };

    const SecretKey key = key_from_bytes(kKat3Key);
    const Block plaintext = block_from_bytes(kKat3Plaintext);
    const Block expected = block_from_bytes(kKat3Ciphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, fourth_kat_vector_nist_cavp) {
    // Another NIST CAVP AES-256 vector with non-zero data throughout.
    constexpr unsigned char kKat4Key[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    constexpr unsigned char kKat4Plaintext[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    constexpr unsigned char kKat4Ciphertext[16] = {
        0xd5, 0xf9, 0x3d, 0x6d, 0x33, 0x11, 0xcb, 0x30, 0x9f, 0x23, 0x62, 0x1b, 0x02, 0xfb, 0xd5, 0xe2,
    };

    const SecretKey key = key_from_bytes(kKat4Key);
    const Block plaintext = block_from_bytes(kKat4Plaintext);
    const Block expected = block_from_bytes(kKat4Ciphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

namespace {
// FIPS-197 Appendix C.1: AES-128 encryption of a single block. Shared with
// cpu_detect.cpp's hardware self-verification via src/kat_vector.hpp.
using aeslib::detail::kKat128Ciphertext;
using aeslib::detail::kKat128Key;
using aeslib::detail::kKat128Plaintext;
} // namespace

AESLIB_TEST(aes_core, software_matches_fips197_aes128_kat) {
    const SecretKey key = key_from_bytes16(kKat128Key);
    const Block plaintext = block_from_bytes(kKat128Plaintext);
    const Block expected = block_from_bytes(kKat128Ciphertext);

    const Block actual = aeslib::detail::aes128_encrypt_block_soft(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, hardware_matches_fips197_aes128_kat_when_available) {
    if (!aeslib::cpu::has_hw_aes()) {
        std::printf("   (skipped: no hardware AES acceleration on this machine)\n");
        return;
    }
    const SecretKey key = key_from_bytes16(kKat128Key);
    const Block plaintext = block_from_bytes(kKat128Plaintext);
    const Block expected = block_from_bytes(kKat128Ciphertext);

    const Block actual = aeslib::detail::aes128_encrypt_block_hw(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, aes128_backends_agree_on_random_blocks) {
    if (!aeslib::cpu::has_hw_aes()) {
        std::printf("   (skipped: no hardware AES acceleration on this machine)\n");
        return;
    }
    for (int trial = 0; trial < 8; ++trial) {
        unsigned char key_bytes[16];
        unsigned char block_bytes[16];
        aeslib::rng::fill_random(reinterpret_cast<std::byte*>(key_bytes), sizeof(key_bytes));
        aeslib::rng::fill_random(reinterpret_cast<std::byte*>(block_bytes), sizeof(block_bytes));

        const SecretKey key = key_from_bytes16(key_bytes);
        const Block block = block_from_bytes(block_bytes);

        const Block soft_result = aeslib::detail::aes128_encrypt_block_soft(key, block);
        const Block hw_result = aeslib::detail::aes128_encrypt_block_hw(key, block);
        CHECK(soft_result == hw_result);
    }
}

#if defined(__riscv) && __riscv_xlen == 64
// The tests above skip whenever cpu::has_hw_aes() is false — correct for
// real hardware, where the extension genuinely might be absent. But this
// project's own qemu-riscv64 CI leg passes -cpu max,zkne=true (QEMU's TCG
// does correctly execute the Zkne instructions under that flag — confirmed
// separately), while cpu::has_hw_aes() still reports false there: Ubuntu
// 24.04's qemu-user-static (8.2.2) predates RISCV_HWPROBE_EXT_ZKNE/ZKND
// existing as bit definitions in its riscv_hwprobe() syscall implementation
// at all, so no CPU flag can make hwprobe report them on that specific
// QEMU version — a detection-reporting gap, not a missing-instruction one.
// These two tests call the riscv backend directly, bypassing
// cpu::has_hw_aes(), specifically so this project's riscv64 CI still
// exercises aes_core_riscv.cpp's real instruction sequence under emulation
// rather than silently skipping it the way the has_hw_aes()-gated tests
// above do on this particular toolchain.
AESLIB_TEST(aes_core, riscv_hardware_matches_fips197_kat_directly) {
    const SecretKey key = key_from_bytes(kKatKey);
    const Block plaintext = block_from_bytes(kKatPlaintext);
    const Block expected = block_from_bytes(kKatCiphertext);

    const Block actual = aeslib::detail::aes256_encrypt_block_riscv(key, plaintext);
    CHECK(actual == expected);
}

AESLIB_TEST(aes_core, riscv_hardware_matches_fips197_aes128_kat_directly) {
    const SecretKey key = key_from_bytes16(kKat128Key);
    const Block plaintext = block_from_bytes(kKat128Plaintext);
    const Block expected = block_from_bytes(kKat128Ciphertext);

    const Block actual = aeslib::detail::aes128_encrypt_block_riscv(key, plaintext);
    CHECK(actual == expected);
}
#endif
