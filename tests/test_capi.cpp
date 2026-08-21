// Exercises the C ABI declared in include/aeslib/capi.h — the boundary the
// rest of the suite never touches (bindings/python/demo.py is the only other
// thing that calls into it). Covers the null-pointer/invalid-argument
// validation documented on every entry point, plus a minimal CTR/GCM
// round-trip end to end through the C API.

#include "aeslib/capi.h"

#include <cstring>
#include <filesystem>
#include <string>

#include "test_support.hpp"

namespace {

aeslib_key_t generate_key(int bits = 256) {
    aeslib_key_t key = nullptr;
    CHECK_EQ(aeslib_key_generate(bits, &key), AESLIB_OK);
    return key;
}

} // namespace

AESLIB_TEST(capi, key_generate_rejects_null_out_key) {
    CHECK_EQ(aeslib_key_generate(256, nullptr), AESLIB_ERR_INVALID_ARGUMENT);
}

AESLIB_TEST(capi, key_generate_rejects_bad_key_size) {
    aeslib_key_t key = nullptr;
    CHECK_EQ(aeslib_key_generate(64, &key), AESLIB_ERR_INVALID_ARGUMENT);
    CHECK(key == nullptr);
}

AESLIB_TEST(capi, key_generate_accepts_128_and_256) {
    aeslib_key_t key128 = generate_key(128);
    aeslib_key_t key256 = generate_key(256);
    CHECK(key128 != nullptr);
    CHECK(key256 != nullptr);
    aeslib_key_free(key128);
    aeslib_key_free(key256);
}

AESLIB_TEST(capi, key_free_null_is_noop) { aeslib_key_free(nullptr); }

AESLIB_TEST(capi, key_save_rejects_null_args) {
    aeslib_key_t key = generate_key();
    CHECK_EQ(aeslib_key_save_to_file(nullptr, "/tmp/whatever.key"), AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_key_save_to_file(key, nullptr), AESLIB_ERR_INVALID_ARGUMENT);
    aeslib_key_free(key);
}

AESLIB_TEST(capi, key_load_rejects_null_args) {
    aeslib_key_t out = nullptr;
    CHECK_EQ(aeslib_key_load_from_file(nullptr, &out), AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_key_load_from_file("/tmp/whatever.key", nullptr), AESLIB_ERR_INVALID_ARGUMENT);
}

AESLIB_TEST(capi, key_save_and_load_round_trip) {
    aeslib_key_t key = generate_key();
    auto path = std::filesystem::temp_directory_path() / "aeslib_test_capi_key.key";
    CHECK_EQ(aeslib_key_save_to_file(key, path.string().c_str()), AESLIB_OK);

    aeslib_key_t loaded = nullptr;
    CHECK_EQ(aeslib_key_load_from_file(path.string().c_str(), &loaded), AESLIB_OK);
    CHECK(loaded != nullptr);

    std::filesystem::remove(path);
    aeslib_key_free(key);
    aeslib_key_free(loaded);
}

AESLIB_TEST(capi, ctr_encrypt_rejects_null_args) {
    aeslib_key_t key = generate_key();
    const uint8_t plaintext[] = {1, 2, 3};
    uint8_t nonce[AESLIB_NONCE_BYTES];
    uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;

    CHECK_EQ(aeslib_ctr_encrypt(nullptr, plaintext, sizeof(plaintext), nonce, &ciphertext, &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_encrypt(key, plaintext, sizeof(plaintext), nullptr, &ciphertext, &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_encrypt(key, plaintext, sizeof(plaintext), nonce, nullptr, &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_encrypt(key, plaintext, sizeof(plaintext), nonce, &ciphertext, nullptr),
             AESLIB_ERR_INVALID_ARGUMENT);
    // Non-null plaintext_len with a null plaintext pointer is invalid...
    CHECK_EQ(aeslib_ctr_encrypt(key, nullptr, sizeof(plaintext), nonce, &ciphertext, &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    // ...but a null plaintext with length 0 is a valid empty-plaintext call.
    CHECK_EQ(aeslib_ctr_encrypt(key, nullptr, 0, nonce, &ciphertext, &ciphertext_len), AESLIB_OK);
    CHECK_EQ(ciphertext_len, static_cast<size_t>(0));
    aeslib_buffer_free(ciphertext);

    aeslib_key_free(key);
}

AESLIB_TEST(capi, ctr_decrypt_rejects_null_args) {
    aeslib_key_t key = generate_key();
    const uint8_t nonce[AESLIB_NONCE_BYTES] = {};
    const uint8_t ciphertext[] = {1, 2, 3};
    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;

    CHECK_EQ(aeslib_ctr_decrypt(nullptr, nonce, ciphertext, sizeof(ciphertext), &plaintext, &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_decrypt(key, nullptr, ciphertext, sizeof(ciphertext), &plaintext, &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_decrypt(key, nonce, nullptr, sizeof(ciphertext), &plaintext, &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_decrypt(key, nonce, ciphertext, sizeof(ciphertext), nullptr, &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_ctr_decrypt(key, nonce, ciphertext, sizeof(ciphertext), &plaintext, nullptr),
             AESLIB_ERR_INVALID_ARGUMENT);

    aeslib_key_free(key);
}

AESLIB_TEST(capi, ctr_round_trip) {
    aeslib_key_t key = generate_key();
    const std::string message = "the quick brown fox jumps over the lazy dog";
    uint8_t nonce[AESLIB_NONCE_BYTES];
    uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;

    CHECK_EQ(aeslib_ctr_encrypt(key, reinterpret_cast<const uint8_t*>(message.data()), message.size(), nonce,
                                 &ciphertext, &ciphertext_len),
             AESLIB_OK);
    CHECK_EQ(ciphertext_len, message.size());

    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;
    CHECK_EQ(aeslib_ctr_decrypt(key, nonce, ciphertext, ciphertext_len, &plaintext, &plaintext_len), AESLIB_OK);
    CHECK_EQ(plaintext_len, message.size());
    CHECK(std::memcmp(plaintext, message.data(), message.size()) == 0);

    aeslib_buffer_free(ciphertext);
    aeslib_buffer_free(plaintext);
    aeslib_key_free(key);
}

AESLIB_TEST(capi, gcm_encrypt_rejects_null_args) {
    aeslib_key_t key = generate_key();
    const uint8_t plaintext[] = {1, 2, 3};
    const uint8_t aad[] = {4, 5};
    uint8_t nonce[AESLIB_NONCE_BYTES];
    uint8_t tag[AESLIB_TAG_BYTES];
    uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;

    CHECK_EQ(aeslib_gcm_encrypt(nullptr, plaintext, sizeof(plaintext), aad, sizeof(aad), nonce, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_encrypt(key, nullptr, sizeof(plaintext), aad, sizeof(aad), nonce, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), nullptr, sizeof(aad), nonce, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), aad, sizeof(aad), nullptr, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), aad, sizeof(aad), nonce, nullptr, &ciphertext,
                                 &ciphertext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(
        aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), aad, sizeof(aad), nonce, tag, nullptr, &ciphertext_len),
        AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), aad, sizeof(aad), nonce, tag, &ciphertext, nullptr),
             AESLIB_ERR_INVALID_ARGUMENT);

    // null aad with aad_len 0 is a valid "no AAD" call.
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext, sizeof(plaintext), nullptr, 0, nonce, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_OK);
    aeslib_buffer_free(ciphertext);

    aeslib_key_free(key);
}

AESLIB_TEST(capi, gcm_decrypt_rejects_null_args) {
    aeslib_key_t key = generate_key();
    const uint8_t nonce[AESLIB_NONCE_BYTES] = {};
    const uint8_t tag[AESLIB_TAG_BYTES] = {};
    const uint8_t ciphertext[] = {1, 2, 3};
    const uint8_t aad[] = {4, 5};
    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;

    CHECK_EQ(aeslib_gcm_decrypt(nullptr, nonce, tag, ciphertext, sizeof(ciphertext), aad, sizeof(aad), &plaintext,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_decrypt(key, nullptr, tag, ciphertext, sizeof(ciphertext), aad, sizeof(aad), &plaintext,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, nullptr, ciphertext, sizeof(ciphertext), aad, sizeof(aad), &plaintext,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, tag, nullptr, sizeof(ciphertext), aad, sizeof(aad), &plaintext,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, tag, ciphertext, sizeof(ciphertext), nullptr, sizeof(aad), &plaintext,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, tag, ciphertext, sizeof(ciphertext), aad, sizeof(aad), nullptr,
                                 &plaintext_len),
             AESLIB_ERR_INVALID_ARGUMENT);
    CHECK_EQ(
        aeslib_gcm_decrypt(key, nonce, tag, ciphertext, sizeof(ciphertext), aad, sizeof(aad), &plaintext, nullptr),
        AESLIB_ERR_INVALID_ARGUMENT);

    aeslib_key_free(key);
}

AESLIB_TEST(capi, gcm_round_trip) {
    aeslib_key_t key = generate_key();
    const std::string message = "attack at dawn";
    const std::string aad_str = "header";
    uint8_t nonce[AESLIB_NONCE_BYTES];
    uint8_t tag[AESLIB_TAG_BYTES];
    uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;

    CHECK_EQ(aeslib_gcm_encrypt(key, reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                                 reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size(), nonce, tag,
                                 &ciphertext, &ciphertext_len),
             AESLIB_OK);

    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, tag, ciphertext, ciphertext_len,
                                 reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size(), &plaintext,
                                 &plaintext_len),
             AESLIB_OK);
    CHECK_EQ(plaintext_len, message.size());
    CHECK(std::memcmp(plaintext, message.data(), message.size()) == 0);

    aeslib_buffer_free(ciphertext);
    aeslib_buffer_free(plaintext);
    aeslib_key_free(key);
}

AESLIB_TEST(capi, gcm_decrypt_tampered_tag_reports_authentication_error) {
    aeslib_key_t key = generate_key();
    const uint8_t plaintext_in[] = {1, 2, 3, 4};
    uint8_t nonce[AESLIB_NONCE_BYTES];
    uint8_t tag[AESLIB_TAG_BYTES];
    uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;
    CHECK_EQ(aeslib_gcm_encrypt(key, plaintext_in, sizeof(plaintext_in), nullptr, 0, nonce, tag, &ciphertext,
                                 &ciphertext_len),
             AESLIB_OK);
    tag[0] ^= 0xFF;

    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;
    CHECK_EQ(aeslib_gcm_decrypt(key, nonce, tag, ciphertext, ciphertext_len, nullptr, 0, &plaintext, &plaintext_len),
             AESLIB_ERR_AUTHENTICATION);
    CHECK(plaintext == nullptr);

    aeslib_buffer_free(ciphertext);
    aeslib_key_free(key);
}

AESLIB_TEST(capi, last_error_message_set_after_failure) {
    aeslib_key_generate(64, nullptr);
    const char* message = aeslib_last_error_message();
    CHECK(message != nullptr);
    CHECK(std::strlen(message) > 0);
}

AESLIB_TEST(capi, buffer_free_null_is_noop) { aeslib_buffer_free(nullptr); }
