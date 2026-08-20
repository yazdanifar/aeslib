#pragma once

#include <cstddef>
#include <vector>

#include "aeslib/container.hpp"
#include "aeslib/key.hpp"

namespace aeslib {

// AES-256 in CTR mode. Stateless with respect to key material (the key is
// passed per call, never stored inside this object), so there's nothing here
// for a caller to accidentally keep alive longer than the key itself.
//
// CTR mode uses the same transform for encryption and decryption
// (plaintext/ciphertext XORed with an AES-encrypted counter stream), so
// encrypt() and decrypt() are literally the same operation — kept as two
// named functions purely for call-site clarity.
class Aes256Ctr {
public:
    // Encrypts `plaintext` under `key`, generating a fresh random nonce
    // internally (see DESIGN.md for the nonce strategy). Returns a container
    // ready to be written to disk with save_container().
    static Container encrypt(const SecretKey& key, const std::vector<std::byte>& plaintext);

    // Decrypts a container previously produced by encrypt() (or read back
    // via load_container()) under `key`.
    static std::vector<std::byte> decrypt(const SecretKey& key, const Container& container);
};

} // namespace aeslib
