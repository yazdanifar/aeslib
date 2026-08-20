/* aeslib C ABI — bonus 3.7 ("Foreign-language interface").
 *
 * Pure C (no C++ constructs), extern "C" linkage, opaque handles, and
 * status-code error reporting — the standard shape for exposing a C++
 * library across a language boundary without dragging C++ name mangling,
 * exceptions, or STL type layout across it. See DESIGN.md's
 * "Foreign-language interface" section for the full rationale.
 *
 * Ownership rules (read before calling anything below):
 *   - Handles obtained from aeslib_key_generate()/aeslib_key_load_from_file()
 *     must be released exactly once with aeslib_key_free().
 *   - Buffers returned via an `out_*` uint8_t** parameter are allocated by
 *     this library and must be released with aeslib_buffer_free() — never
 *     with the caller's own free()/delete[]. Mixing allocators across a
 *     shared-library boundary (especially on Windows, where a DLL and its
 *     caller can have distinct CRT heaps) is undefined behavior.
 *   - No function here throws or lets a C++ exception cross into the
 *     caller; failures are reported via the aeslib_status return value,
 *     with human-readable detail available from aeslib_last_error_message().
 */
#ifndef AESLIB_CAPI_H
#define AESLIB_CAPI_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(AESLIB_C_BUILDING_DLL)
#    define AESLIB_C_API __declspec(dllexport)
#  else
#    define AESLIB_C_API __declspec(dllimport)
#  endif
#else
#  define AESLIB_C_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Fixed sizes, duplicated here (rather than shared via a C++ header) since
 * this header must stay includable from plain C: matches
 * aeslib::kNonceSizeBytes / aeslib::kGcmTagSizeBytes in container.hpp /
 * aes_gcm.hpp. */
#define AESLIB_NONCE_BYTES 12
#define AESLIB_TAG_BYTES 16

/* Opaque handle wrapping an aeslib::SecretKey. The C header never sees the
 * C++ class layout — only ever a pointer to it. */
typedef struct aeslib_key aeslib_key;
typedef aeslib_key* aeslib_key_t;

typedef enum aeslib_status {
    AESLIB_OK = 0,
    AESLIB_ERR_INVALID_ARGUMENT = 1,
    AESLIB_ERR_IO = 2,
    AESLIB_ERR_FORMAT = 3,
    AESLIB_ERR_LIMIT = 4,
    AESLIB_ERR_AUTHENTICATION = 5,
    AESLIB_ERR_UNKNOWN = 6
} aeslib_status;

/* Mirrors aeslib::Backend. */
typedef enum aeslib_backend {
    AESLIB_BACKEND_SOFTWARE = 0,
    AESLIB_BACKEND_HARDWARE = 1
} aeslib_backend;

/* Human-readable detail for the most recent failing call made on the
 * current thread. Valid until the next aeslib_* call on this thread;
 * copy it if you need it to outlive that. Never null. */
AESLIB_C_API const char* aeslib_last_error_message(void);

/* Returns the hardware/software dispatch decision for this process (see
 * aeslib::active_backend()). */
AESLIB_C_API aeslib_backend aeslib_active_backend(void);

/* Generates a fresh key via the OS CSPRNG. key_size_bits must be 128 or
 * 256. *out_key is set only on AESLIB_OK. */
AESLIB_C_API aeslib_status aeslib_key_generate(int key_size_bits, aeslib_key_t* out_key);

/* Releases a handle obtained from aeslib_key_generate()/
 * aeslib_key_load_from_file(). No-op if key is NULL. */
AESLIB_C_API void aeslib_key_free(aeslib_key_t key);

/* Writes the key to its own file (aeslib::SecretKey::save_to_file). */
AESLIB_C_API aeslib_status aeslib_key_save_to_file(aeslib_key_t key, const char* path);

/* Loads a key previously written by aeslib_key_save_to_file(). *out_key is
 * set only on AESLIB_OK. */
AESLIB_C_API aeslib_status aeslib_key_load_from_file(const char* path, aeslib_key_t* out_key);

/* AES-256-CTR (aeslib::Aes256Ctr). Encrypts `plaintext` under `key`,
 * writing a fresh random nonce to out_nonce (exactly AESLIB_NONCE_BYTES)
 * and allocating *out_ciphertext (release with aeslib_buffer_free). */
AESLIB_C_API aeslib_status aeslib_ctr_encrypt(aeslib_key_t key, const uint8_t* plaintext,
                                               size_t plaintext_len,
                                               uint8_t out_nonce[AESLIB_NONCE_BYTES],
                                               uint8_t** out_ciphertext, size_t* out_ciphertext_len);

/* Decrypts a nonce/ciphertext pair produced by aeslib_ctr_encrypt() (or an
 * equivalent CTR encryption under the same key/nonce/counter convention).
 * Allocates *out_plaintext (release with aeslib_buffer_free). */
AESLIB_C_API aeslib_status aeslib_ctr_decrypt(aeslib_key_t key,
                                               const uint8_t nonce[AESLIB_NONCE_BYTES],
                                               const uint8_t* ciphertext, size_t ciphertext_len,
                                               uint8_t** out_plaintext, size_t* out_plaintext_len);

/* AES-GCM (aeslib::AesGcm), AES-128 or AES-256 depending on `key`.
 * `aad`/`aad_len` may be NULL/0. Writes a fresh random nonce to out_nonce
 * and the authentication tag to out_tag, allocating *out_ciphertext
 * (release with aeslib_buffer_free). */
AESLIB_C_API aeslib_status aeslib_gcm_encrypt(aeslib_key_t key, const uint8_t* plaintext,
                                               size_t plaintext_len, const uint8_t* aad,
                                               size_t aad_len,
                                               uint8_t out_nonce[AESLIB_NONCE_BYTES],
                                               uint8_t out_tag[AESLIB_TAG_BYTES],
                                               uint8_t** out_ciphertext, size_t* out_ciphertext_len);

/* Decrypts and authenticates a GCM ciphertext produced by
 * aeslib_gcm_encrypt(). Returns AESLIB_ERR_AUTHENTICATION (and allocates
 * nothing) if the tag doesn't verify against `nonce`/`tag`/`aad`/
 * `ciphertext` as given — the ciphertext is never decrypted before
 * authentication succeeds. Otherwise allocates *out_plaintext (release with
 * aeslib_buffer_free). */
AESLIB_C_API aeslib_status aeslib_gcm_decrypt(aeslib_key_t key,
                                               const uint8_t nonce[AESLIB_NONCE_BYTES],
                                               const uint8_t tag[AESLIB_TAG_BYTES],
                                               const uint8_t* ciphertext, size_t ciphertext_len,
                                               const uint8_t* aad, size_t aad_len,
                                               uint8_t** out_plaintext, size_t* out_plaintext_len);

/* Releases a buffer returned via an out_* parameter above. Safe to call
 * with NULL. */
AESLIB_C_API void aeslib_buffer_free(uint8_t* buffer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AESLIB_CAPI_H */
