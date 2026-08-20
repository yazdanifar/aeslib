// End-to-end harness for the aeslib library: generates a sample plaintext
// file, generates a key, encrypts, stores key and ciphertext to separate
// files, reloads both from disk, decrypts, and verifies the round trip.

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/backend.hpp"
#include "aeslib/container.hpp"
#include "aeslib/key.hpp"

namespace {

std::vector<std::byte> make_sample_plaintext() {
    const std::string_view text =
        "The quick brown fox jumps over the lazy dog. AES-256-CTR round-trip "
        "test payload for the Spara take-home challenge.\n";
    std::vector<std::byte> bytes(text.size());
    std::transform(text.begin(), text.end(), bytes.begin(),
                    [](char c) { return static_cast<std::byte>(c); });
    return bytes;
}

} // namespace

int main() {
    const std::filesystem::path plaintext_path = "sample_plaintext.bin";
    const std::filesystem::path key_path = "sample.key";
    const std::filesystem::path ciphertext_path = "sample_ciphertext.aesc";

    try {
        std::cout << "Backend in use: "
                  << (aeslib::active_backend() == aeslib::Backend::Hardware ? "Hardware (AES-NI)" : "Software")
                  << '\n';

        // 1. Load (or generate) a sample plaintext file.
        std::vector<std::byte> plaintext;
        if (std::filesystem::exists(plaintext_path)) {
            plaintext = aeslib::read_file(plaintext_path);
            std::cout << "Loaded existing sample plaintext from " << plaintext_path << '\n';
        } else {
            plaintext = make_sample_plaintext();
            aeslib::write_file(plaintext_path, plaintext);
            std::cout << "Generated sample plaintext at " << plaintext_path << '\n';
        }

        // 2. Generate a key.
        aeslib::SecretKey key = aeslib::SecretKey::generate();

        // 3. Encrypt the file's contents.
        aeslib::Container container = aeslib::Aes256Ctr::encrypt(key, plaintext);

        // 4. Store the encrypted result and the key, separately, to disk.
        aeslib::save_container(container, ciphertext_path);
        key.save_to_file(key_path);
        std::cout << "Stored ciphertext at " << ciphertext_path << " and key at " << key_path << '\n';

        // 5. Load the encrypted result back from disk.
        aeslib::Container loaded_container = aeslib::load_container(ciphertext_path);
        aeslib::SecretKey loaded_key = aeslib::SecretKey::load_from_file(key_path);

        // 6. Decrypt it.
        std::vector<std::byte> decrypted = aeslib::Aes256Ctr::decrypt(loaded_key, loaded_container);

        // 7. Verify the round-tripped plaintext matches the original.
        if (decrypted == plaintext) {
            std::cout << "SUCCESS: round-tripped plaintext matches the original (" << plaintext.size()
                      << " bytes).\n";
            return EXIT_SUCCESS;
        }
        std::cout << "FAILURE: round-tripped plaintext does not match the original.\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "FAILURE: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
