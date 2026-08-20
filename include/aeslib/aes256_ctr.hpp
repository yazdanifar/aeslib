#pragma once

#include <cstddef>
#include <type_traits>
#include <vector>

#include "aeslib/byte_view.hpp"
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

    // Bonus: generic support for other types via templates (see
    // byte_view.hpp and DESIGN.md). Encrypts any byte-viewable T — a
    // contiguous container of trivially copyable elements (std::vector<X>,
    // std::array<X,N>, std::string, ...) or a single trivially copyable
    // object (e.g. a plain struct) — by viewing its storage as raw bytes.
    // Excluded from matching std::vector<std::byte> itself so the exact
    // overload above always handles that baseline case.
    template <typename T, typename = std::enable_if_t<
                               detail::is_byte_viewable_v<T> &&
                               !std::is_same_v<T, std::vector<std::byte>>>>
    static Container encrypt(const SecretKey& key, const T& plaintext) {
        return encrypt(key, detail::to_byte_vector(plaintext));
    }

    // Decrypts a container previously produced by encrypt() (or read back
    // via load_container()) under `key`.
    static std::vector<std::byte> decrypt(const SecretKey& key, const Container& container);

    // Bonus: generic support for other types via templates. Decrypts into
    // any byte-viewable T, reinterpreting the decrypted bytes as T's storage
    // (see byte_view.hpp for the exact-length/element-count rules). A
    // separate name from decrypt() rather than an overload, since T can't be
    // deduced from the arguments — call as decrypt_as<T>(key, container).
    // Throws FormatError if the decrypted byte count doesn't match what T
    // requires (e.g. wrong sizeof(T), or not a whole multiple of an element
    // size for a container type).
    template <typename T, typename = std::enable_if_t<detail::is_byte_viewable_v<T>>>
    static T decrypt_as(const SecretKey& key, const Container& container) {
        return detail::from_byte_vector<T>(decrypt(key, container));
    }
};

} // namespace aeslib
