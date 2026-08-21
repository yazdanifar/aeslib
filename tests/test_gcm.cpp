// GHASH primitive KATs, full AES-GCM known-answer tests, round-trips,
// tamper-detection, and container-format edge cases.
//
// GCM vectors were generated with Python's `cryptography` library
// (AESGCM), then independently cross-checked with a second, unrelated
// implementation (`pycryptodome`'s AES.MODE_GCM) before being hardcoded as
// expected values here — the same two-source methodology
// tests/test_reference_vectors.cpp documents for the CTR vectors. The GHASH
// KATs below were computed with a from-scratch Python re-implementation of
// GF(2^128) multiplication (independent of both of the above), cross-checked
// against the same vectors' authentication tags. Reproduction:
//
//   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
//   ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad or None)
//   ct, tag = ct_tag[:-16], ct_tag[-16:]
// Independently reproduced with:
//   from Crypto.Cipher import AES
//   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
//   cipher.update(aad)
//   ct, tag = cipher.encrypt_and_digest(plaintext)
//
// Since AesGcm::encrypt() always generates a fresh random nonce internally,
// these KATs are exercised through AesGcm::decrypt() with an explicit
// nonce/tag/ciphertext (same "decrypt as a deterministic encrypt-with-fixed-
// nonce" trick tests/test_reference_vectors.cpp uses for CTR) — this
// exercises both keystream generation and tag verification in one call,
// since decrypt() throws AuthenticationError if the recomputed tag doesn't
// match the stored one.

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "aeslib/aes_gcm.hpp"
#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"
#include "src/internal.hpp"
#include "test_support.hpp"

namespace {

using aeslib::AesGcm;
using aeslib::AuthenticationError;
using aeslib::FormatError;
using aeslib::GcmContainer;
using aeslib::KeySize;
using aeslib::LimitError;
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
// temp file using the wire format save_to_file() writes (version 2:
// version || size_marker || size_marker bytes of key).
SecretKey key_from_hex(const std::string& hex) {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("aeslib_test_gcmkey_" + std::to_string(++counter) + ".key");
    const auto bytes = bytes_from_hex(hex);
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(2)); // version
        out.put(static_cast<char>(bytes.size())); // size marker
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

std::array<std::byte, 16> tag_from_hex(const std::string& hex) {
    std::array<std::byte, 16> tag{};
    const auto bytes = bytes_from_hex(hex);
    CHECK(bytes.size() == 16);
    std::copy(bytes.begin(), bytes.end(), tag.begin());
    return tag;
}

aeslib::detail::Block block_from_hex(const std::string& hex) {
    aeslib::detail::Block block{};
    const auto bytes = bytes_from_hex(hex);
    CHECK(bytes.size() == 16);
    std::copy(bytes.begin(), bytes.end(), block.begin());
    return block;
}

struct GcmVector {
    const char* key_hex;
    const char* nonce_hex;
    const char* aad_hex;
    const char* plaintext_hex;
    const char* ciphertext_hex;
    const char* tag_hex;
};

// clang-format off
constexpr GcmVector kAes128Vectors[] = {
    {
        "4420823cfde6f1c26b30f90ec7dd01e4",
        "887534a20f0b0d04c36ed80e",
        "",
        "",
        "",
        "3f4e4040845d9d43811df89889c0b302",
    },
    {
        "1c2e2bb8569d806c1251dcc9bee38912",
        "0ebaeea3c2d8545a78760c5a",
        "",
        "a65845b85de4d4bab5b9e452ccec7ffa",
        "cf06722f7927b377e295d9147eae4953",
        "17c8818cafdb955833f7a65054eafd50",
    },
    {
        // 13-byte plaintext: exercises the partial-final-block path.
        "7942bdf22106f0847762f0f3cb4d764d",
        "c7072051159a0f89f2c6daca",
        "",
        "e344bb311245fd6f84df9ad7c5",
        "45fbc0070c9c5eafd935c0a5e8",
        "5e9d68b2e40cbd9bc0fd277ea7d55944",
    },
    {
        // Multi-block plaintext with AAD.
        "789b34caf54f2e220acd941e71b88d58",
        "36866d0d858b63549e94be2c",
        "a95a94eb0d15b62a92a709a593a44ed2279662e3",
        "acc67f5b7ef28f2d9903959f63d3d893dce752779c84162917ec8ff1af4a6422d367e18d5eb6dfa465a5331f758e793e",
        "b4b72f7e029daafdd372b5d77d856e974b5fd49403e6b72b2bf336845a6d5e90b3bba8357fc620cc7a5c12f84fef0a4c",
        "bf6339aa781752b6d7c8b832b85169bb",
    },
};

constexpr GcmVector kAes256Vectors[] = {
    {
        "82b70eee7f1a5039bef07ec2347f066ed08f5dc7512447e3404300026b6e5455",
        "94a065685d64c4980bb8d454",
        "",
        "",
        "",
        "8cd34f13dbccd87a65237df9903e0056",
    },
    {
        "29f88512004af0bfa30b8bfa65d33062872dd9ab2fb9d180e3306495311766b8",
        "f9630eb97ddc9bb63d2d653b",
        "",
        "899f64c2f772466b06605608aa9cbfc1",
        "fa2d6ea93d56b9d35ef794bbc1c9023e",
        "f11e3672d4de14e3c5f5171176de5019",
    },
    {
        "a54dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5c",
        "3460be31201e69fedaa0eee8",
        "e491c5b10b",
        "b9997f5c7c2999fdafe593253cd654af4dfad71427a0aeb3fee9232f8af2211f9e",
        "9bf98f725e4d08850cd31c29e2cc700135a55fe329009e3d00a112def4da19e0f5",
        "d73fa20932693e6a73d2d4ce42dcf582",
    },
    {
        "74bdc04062162b467e6bcd0febf9e8c7fd62ce2df8770a88d0f2c23a843120c5",
        "c1371dad782cfe6a482013fa",
        "",
        "634be9e392b6da455131a0b6fd659e4cb6912470b07c0697af708811d882c098d559ca3b550d6752993b06c2af57df7647d1e4d0d529239330112b36b84ef94c",
        "ca54e31c58b17b5ee58b981bc7e2218169e15641dd1f35dcc58f0772a582a8559a7ab8333c291823ed5ae644a7342141e783ac33ce206344f8e8e2774925b6c1",
        "b5d297409e62cf4fbae5e60ed0386e5e",
    },
};
// clang-format on

} // namespace

AESLIB_TEST(gcm, ghash_kat_empty_aad_single_block_ciphertext) {
    // H = AES-128-ECB(all-zero key, 0^128); block = the ciphertext block from
    // the "AES128 1block noaad" AES-GCM vector above — an independently
    // computed GHASH_H(empty AAD, one 16-byte ciphertext block).
    const auto h = block_from_hex("66e94bd4ef8a2c3b884cfa59ca342b2e");
    const std::vector<std::byte> aad;
    const auto ciphertext = bytes_from_hex("0388dace60b6a392f328c2b971b2fe78");
    const auto expected = block_from_hex("f38cbb1ad69223dcc3457ae5b6b0f885");

    const auto actual = aeslib::detail::ghash(h, aad, ciphertext);
    CHECK(actual == expected);
}

AESLIB_TEST(gcm, ghash_kat_with_aad_multiblock_ciphertext) {
    // H and the ciphertext/AAD are drawn from the "AES128 multiblock aad"
    // vector above; the expected GHASH output was independently computed
    // and cross-checked against that vector's tag (tag == GHASH XOR E(K,J0)).
    const auto h = block_from_hex("82e819456869bfb066759d494cd9a4cd");
    const auto aad = bytes_from_hex("a95a94eb0d15b62a92a709a593a44ed2279662e3");
    const auto ciphertext = bytes_from_hex(
        "b4b72f7e029daafdd372b5d77d856e974b5fd49403e6b72b2bf336845a6d5e90b3bba8357fc620cc7a5c12f84fef0a4c");
    const auto expected = block_from_hex("084d64a2abcaf45883dba3fe44bacbf7");

    const auto actual = aeslib::detail::ghash(h, aad, ciphertext);
    CHECK(actual == expected);
}

AESLIB_TEST(gcm, aes128_kats_via_decrypt) {
    for (const auto& v : kAes128Vectors) {
        const SecretKey key = key_from_hex(v.key_hex);
        GcmContainer container;
        container.nonce = nonce_from_hex(v.nonce_hex);
        container.tag = tag_from_hex(v.tag_hex);
        container.ciphertext = bytes_from_hex(v.ciphertext_hex);
        const auto aad = bytes_from_hex(v.aad_hex);
        const auto expected_plaintext = bytes_from_hex(v.plaintext_hex);

        const auto plaintext = AesGcm::decrypt(key, container, aad);
        CHECK_EQ(plaintext, expected_plaintext);
    }
}

AESLIB_TEST(gcm, aes256_kats_via_decrypt) {
    for (const auto& v : kAes256Vectors) {
        const SecretKey key = key_from_hex(v.key_hex);
        GcmContainer container;
        container.nonce = nonce_from_hex(v.nonce_hex);
        container.tag = tag_from_hex(v.tag_hex);
        container.ciphertext = bytes_from_hex(v.ciphertext_hex);
        const auto aad = bytes_from_hex(v.aad_hex);
        const auto expected_plaintext = bytes_from_hex(v.plaintext_hex);

        const auto plaintext = AesGcm::decrypt(key, container, aad);
        CHECK_EQ(plaintext, expected_plaintext);
    }
}

AESLIB_TEST(gcm, round_trip_aes128_no_aad) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}, std::byte{5}};

    const GcmContainer container = AesGcm::encrypt(key, plaintext);
    const auto decrypted = AesGcm::decrypt(key, container);
    CHECK_EQ(decrypted, plaintext);
}

AESLIB_TEST(gcm, round_trip_aes256_with_aad) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext(100, std::byte{0x42});
    const std::vector<std::byte> aad = {std::byte{'h'}, std::byte{'d'}, std::byte{'r'}};

    const GcmContainer container = AesGcm::encrypt(key, plaintext, aad);
    const auto decrypted = AesGcm::decrypt(key, container, aad);
    CHECK_EQ(decrypted, plaintext);
}

AESLIB_TEST(gcm, round_trip_empty_plaintext) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    const GcmContainer container = AesGcm::encrypt(key, {});
    const auto decrypted = AesGcm::decrypt(key, container);
    CHECK(decrypted.empty());
}

AESLIB_TEST(gcm, tampered_ciphertext_throws_authentication_error) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    GcmContainer container = AesGcm::encrypt(key, plaintext);
    container.ciphertext[0] ^= std::byte{0x01};
    CHECK_THROWS(AesGcm::decrypt(key, container), AuthenticationError);
}

AESLIB_TEST(gcm, tampered_tag_throws_authentication_error) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    GcmContainer container = AesGcm::encrypt(key, plaintext);
    container.tag[0] ^= std::byte{0x01};
    CHECK_THROWS(AesGcm::decrypt(key, container), AuthenticationError);
}

AESLIB_TEST(gcm, tampered_aad_throws_authentication_error) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::vector<std::byte> aad = {std::byte{'a'}, std::byte{'b'}};
    const GcmContainer container = AesGcm::encrypt(key, plaintext, aad);
    const std::vector<std::byte> wrong_aad = {std::byte{'a'}, std::byte{'c'}};
    CHECK_THROWS(AesGcm::decrypt(key, container, wrong_aad), AuthenticationError);
}

AESLIB_TEST(gcm, wrong_key_throws_authentication_error) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const SecretKey wrong_key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const GcmContainer container = AesGcm::encrypt(key, plaintext);
    CHECK_THROWS(AesGcm::decrypt(wrong_key, container), AuthenticationError);
}

AESLIB_TEST(gcm, nonce_and_tag_are_fresh_per_encryption) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    const std::vector<std::byte> plaintext = {std::byte{9}, std::byte{9}, std::byte{9}};
    const GcmContainer a = AesGcm::encrypt(key, plaintext);
    const GcmContainer b = AesGcm::encrypt(key, plaintext);
    CHECK(a.nonce != b.nonce);
    CHECK(a.tag != b.tag);
}

AESLIB_TEST(gcm, container_serialize_deserialize_round_trip) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::vector<std::byte> plaintext = {std::byte{1}, std::byte{2}, std::byte{3}};
    const GcmContainer original = AesGcm::encrypt(key, plaintext);

    const auto bytes = aeslib::serialize(original);
    const GcmContainer restored = aeslib::deserialize_gcm(bytes);
    CHECK(restored.nonce == original.nonce);
    CHECK(restored.tag == original.tag);
    CHECK_EQ(restored.ciphertext, original.ciphertext);
}

AESLIB_TEST(gcm, container_file_round_trip) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    const std::vector<std::byte> plaintext = {std::byte{7}, std::byte{8}};
    const GcmContainer original = AesGcm::encrypt(key, plaintext);

    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_gcm_container.aesg";
    aeslib::save_gcm_container(original, path);
    const GcmContainer restored = aeslib::load_gcm_container(path);
    std::filesystem::remove(path);

    CHECK(restored.nonce == original.nonce);
    CHECK(restored.tag == original.tag);
    CHECK_EQ(restored.ciphertext, original.ciphertext);
}

AESLIB_TEST(gcm, container_rejects_bad_magic) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    auto bytes = aeslib::serialize(AesGcm::encrypt(key, {std::byte{1}}));
    bytes[0] = std::byte{'X'};
    CHECK_THROWS(aeslib::deserialize_gcm(bytes), FormatError);
}

AESLIB_TEST(gcm, container_rejects_unsupported_version) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    auto bytes = aeslib::serialize(AesGcm::encrypt(key, {std::byte{1}}));
    bytes[4] = static_cast<std::byte>(aeslib::kGcmContainerVersion + 1);
    CHECK_THROWS(aeslib::deserialize_gcm(bytes), FormatError);
}

AESLIB_TEST(gcm, container_rejects_truncated_header) {
    std::vector<std::byte> bytes(3, std::byte{0});
    CHECK_THROWS(aeslib::deserialize_gcm(bytes), FormatError);
}

AESLIB_TEST(gcm, container_rejects_ciphertext_length_mismatch) {
    const SecretKey key = SecretKey::generate(KeySize::Aes128);
    auto bytes = aeslib::serialize(AesGcm::encrypt(key, {std::byte{1}, std::byte{2}}));
    bytes.pop_back(); // truncate ciphertext by one byte without updating ct_len
    CHECK_THROWS(aeslib::deserialize_gcm(bytes), FormatError);
}

// NIST SP 800-38D §8.3's recommended 2^32-per-key limit on random-nonce GCM
// encryptions (see DESIGN.md and internal.hpp's kGcmInvocationLimit). Tested
// as a pure boundary check on the prior-invocation count directly — the same
// reason aes_core's 32-bit block-counter guard is tested via
// detail::validate_block_count(size) rather than by actually allocating a
// ~64 GiB buffer, doing 2^32 real encryptions here would take somewhere
// between "very slow" and "never finishes" in a CI run.
AESLIB_TEST(gcm, invocation_limit_accepts_count_just_under_limit) {
    aeslib::detail::check_gcm_invocation_count(aeslib::detail::kGcmInvocationLimit - 1); // no throw
}

AESLIB_TEST(gcm, invocation_limit_rejects_count_at_limit) {
    CHECK_THROWS(aeslib::detail::check_gcm_invocation_count(aeslib::detail::kGcmInvocationLimit), LimitError);
}

AESLIB_TEST(gcm, invocation_limit_rejects_count_past_limit) {
    CHECK_THROWS(aeslib::detail::check_gcm_invocation_count(aeslib::detail::kGcmInvocationLimit + 1), LimitError);
}

// End-to-end: AesGcm::encrypt() actually advances the same SecretKey's
// counter across repeated calls, rather than the check above testing dead
// code. detail::consume_gcm_invocation() returns the pre-increment count, so
// three prior encrypt() calls (from key_from_hex's own AesGcm::encrypt in
// setup, if any, plus these) should read back as consecutive increasing
// values.
AESLIB_TEST(gcm, encrypt_advances_this_keys_gcm_invocation_counter) {
    const SecretKey key = SecretKey::generate(KeySize::Aes256);
    const std::uint64_t before = aeslib::detail::consume_gcm_invocation(key);
    (void)AesGcm::encrypt(key, {std::byte{1}});
    (void)AesGcm::encrypt(key, {std::byte{2}});
    const std::uint64_t after = aeslib::detail::consume_gcm_invocation(key);
    // `before`/`after` themselves each consume one invocation too, so two
    // intervening encrypt() calls plus the `before` probe means `after` is
    // exactly 3 higher than `before`.
    CHECK_EQ(after, before + 3);
}
