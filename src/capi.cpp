// Implementation of the C ABI declared in include/aeslib/capi.h. Every
// exported function is a thin wrapper: validate arguments, call into the
// existing C++ API, translate the result (or a caught exception) into an
// aeslib_status. No C++ exception is ever allowed to unwind across an
// extern "C" boundary — that's undefined behavior for a caller in another
// language, so every function body below is a try/catch that terminates
// locally.

#include "aeslib/capi.h"

#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/aes_gcm.hpp"
#include "aeslib/backend.hpp"
#include "aeslib/container.hpp"
#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"

// Opaque struct definition — only this translation unit knows a
// aeslib_key_t is really an aeslib::SecretKey* under the hood.
struct aeslib_key {
    aeslib::SecretKey key;
};

namespace {

thread_local std::string g_last_error;

void set_last_error(const std::string& message) { g_last_error = message; }

// Converts an in-flight exception (must be called from within a catch
// block) into an aeslib_status, recording its message for
// aeslib_last_error_message(). Centralizing this mapping is what lets every
// wrapper function below stay a one-line try/catch.
aeslib_status translate_exception() {
    try {
        throw;
    } catch (const aeslib::AuthenticationError& e) {
        set_last_error(e.what());
        return AESLIB_ERR_AUTHENTICATION;
    } catch (const aeslib::LimitError& e) {
        set_last_error(e.what());
        return AESLIB_ERR_LIMIT;
    } catch (const aeslib::FormatError& e) {
        set_last_error(e.what());
        return AESLIB_ERR_FORMAT;
    } catch (const aeslib::IoError& e) {
        set_last_error(e.what());
        return AESLIB_ERR_IO;
    } catch (const std::exception& e) {
        set_last_error(e.what());
        return AESLIB_ERR_UNKNOWN;
    } catch (...) {
        set_last_error("unknown non-standard-exception failure");
        return AESLIB_ERR_UNKNOWN;
    }
}

// Copies `bytes` into a freshly heap-allocated buffer the caller will later
// release via aeslib_buffer_free(). Paired allocator on both ends (new[]
// here, delete[] in aeslib_buffer_free) is what makes that pairing safe
// across the shared-library boundary.
void allocate_output(const std::vector<std::byte>& bytes, uint8_t** out, size_t* out_len) {
    auto* buffer = new uint8_t[bytes.empty() ? 1 : bytes.size()];
    if (!bytes.empty()) {
        std::memcpy(buffer, bytes.data(), bytes.size());
    }
    *out = buffer;
    *out_len = bytes.size();
}

std::vector<std::byte> to_bytes(const uint8_t* data, size_t len) {
    const auto* p = reinterpret_cast<const std::byte*>(data);
    return std::vector<std::byte>(p, p + len);
}

} // namespace

extern "C" {

const char* aeslib_last_error_message(void) { return g_last_error.c_str(); }

aeslib_backend aeslib_active_backend(void) {
    return aeslib::active_backend() == aeslib::Backend::Hardware ? AESLIB_BACKEND_HARDWARE
                                                                  : AESLIB_BACKEND_SOFTWARE;
}

aeslib_status aeslib_key_generate(int key_size_bits, aeslib_key_t* out_key) {
    if (out_key == nullptr) {
        set_last_error("out_key must not be null");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    if (key_size_bits != 128 && key_size_bits != 256) {
        set_last_error("key_size_bits must be 128 or 256");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        const auto size = key_size_bits == 128 ? aeslib::KeySize::Aes128 : aeslib::KeySize::Aes256;
        auto handle = std::make_unique<aeslib_key>(aeslib_key{aeslib::SecretKey::generate(size)});
        *out_key = handle.release();
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

void aeslib_key_free(aeslib_key_t key) { delete key; }

aeslib_status aeslib_key_save_to_file(aeslib_key_t key, const char* path) {
    if (key == nullptr || path == nullptr) {
        set_last_error("key and path must not be null");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        key->key.save_to_file(path);
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

aeslib_status aeslib_key_load_from_file(const char* path, aeslib_key_t* out_key) {
    if (path == nullptr || out_key == nullptr) {
        set_last_error("path and out_key must not be null");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        auto handle =
            std::make_unique<aeslib_key>(aeslib_key{aeslib::SecretKey::load_from_file(path)});
        *out_key = handle.release();
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

aeslib_status aeslib_ctr_encrypt(aeslib_key_t key, const uint8_t* plaintext, size_t plaintext_len,
                                  uint8_t out_nonce[AESLIB_NONCE_BYTES], uint8_t** out_ciphertext,
                                  size_t* out_ciphertext_len) {
    if (key == nullptr || (plaintext == nullptr && plaintext_len != 0) || out_nonce == nullptr ||
        out_ciphertext == nullptr || out_ciphertext_len == nullptr) {
        set_last_error("invalid argument to aeslib_ctr_encrypt");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        const aeslib::Container container =
            aeslib::Aes256Ctr::encrypt(key->key, to_bytes(plaintext, plaintext_len));
        static_assert(aeslib::kNonceSizeBytes == AESLIB_NONCE_BYTES,
                      "capi.h's AESLIB_NONCE_BYTES must match aeslib::kNonceSizeBytes");
        std::memcpy(out_nonce, container.nonce.data(), AESLIB_NONCE_BYTES);
        allocate_output(container.ciphertext, out_ciphertext, out_ciphertext_len);
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

aeslib_status aeslib_ctr_decrypt(aeslib_key_t key, const uint8_t nonce[AESLIB_NONCE_BYTES],
                                  const uint8_t* ciphertext, size_t ciphertext_len,
                                  uint8_t** out_plaintext, size_t* out_plaintext_len) {
    if (key == nullptr || nonce == nullptr || (ciphertext == nullptr && ciphertext_len != 0) ||
        out_plaintext == nullptr || out_plaintext_len == nullptr) {
        set_last_error("invalid argument to aeslib_ctr_decrypt");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        aeslib::Container container;
        std::memcpy(container.nonce.data(), nonce, AESLIB_NONCE_BYTES);
        container.ciphertext = to_bytes(ciphertext, ciphertext_len);
        const std::vector<std::byte> plaintext = aeslib::Aes256Ctr::decrypt(key->key, container);
        allocate_output(plaintext, out_plaintext, out_plaintext_len);
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

aeslib_status aeslib_gcm_encrypt(aeslib_key_t key, const uint8_t* plaintext, size_t plaintext_len,
                                  const uint8_t* aad, size_t aad_len,
                                  uint8_t out_nonce[AESLIB_NONCE_BYTES],
                                  uint8_t out_tag[AESLIB_TAG_BYTES], uint8_t** out_ciphertext,
                                  size_t* out_ciphertext_len) {
    if (key == nullptr || (plaintext == nullptr && plaintext_len != 0) ||
        (aad == nullptr && aad_len != 0) || out_nonce == nullptr || out_tag == nullptr ||
        out_ciphertext == nullptr || out_ciphertext_len == nullptr) {
        set_last_error("invalid argument to aeslib_gcm_encrypt");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        const aeslib::GcmContainer container = aeslib::AesGcm::encrypt(
            key->key, to_bytes(plaintext, plaintext_len), to_bytes(aad, aad_len));
        static_assert(aeslib::kGcmNonceSizeBytes == AESLIB_NONCE_BYTES,
                      "capi.h's AESLIB_NONCE_BYTES must match aeslib::kGcmNonceSizeBytes");
        static_assert(aeslib::kGcmTagSizeBytes == AESLIB_TAG_BYTES,
                      "capi.h's AESLIB_TAG_BYTES must match aeslib::kGcmTagSizeBytes");
        std::memcpy(out_nonce, container.nonce.data(), AESLIB_NONCE_BYTES);
        std::memcpy(out_tag, container.tag.data(), AESLIB_TAG_BYTES);
        allocate_output(container.ciphertext, out_ciphertext, out_ciphertext_len);
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

aeslib_status aeslib_gcm_decrypt(aeslib_key_t key, const uint8_t nonce[AESLIB_NONCE_BYTES],
                                  const uint8_t tag[AESLIB_TAG_BYTES], const uint8_t* ciphertext,
                                  size_t ciphertext_len, const uint8_t* aad, size_t aad_len,
                                  uint8_t** out_plaintext, size_t* out_plaintext_len) {
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (ciphertext == nullptr && ciphertext_len != 0) || (aad == nullptr && aad_len != 0) ||
        out_plaintext == nullptr || out_plaintext_len == nullptr) {
        set_last_error("invalid argument to aeslib_gcm_decrypt");
        return AESLIB_ERR_INVALID_ARGUMENT;
    }
    try {
        aeslib::GcmContainer container;
        std::memcpy(container.nonce.data(), nonce, AESLIB_NONCE_BYTES);
        std::memcpy(container.tag.data(), tag, AESLIB_TAG_BYTES);
        container.ciphertext = to_bytes(ciphertext, ciphertext_len);
        const std::vector<std::byte> plaintext =
            aeslib::AesGcm::decrypt(key->key, container, to_bytes(aad, aad_len));
        allocate_output(plaintext, out_plaintext, out_plaintext_len);
        return AESLIB_OK;
    } catch (...) {
        return translate_exception();
    }
}

void aeslib_buffer_free(uint8_t* buffer) { delete[] buffer; }

} // extern "C"
