// libFuzzer harness for aeslib::deserialize_gcm() (include/aeslib/aes_gcm.hpp)
// — the parser for the GCM container's on-disk format (magic, nonce, tag,
// ct_len, ciphertext), the AEAD-mode counterpart to fuzz_container.cpp. See
// that file's header comment for the length-field audit finding, which
// applies identically here (src/aes_gcm.cpp uses the same
// checked-before-use ct_len pattern as src/container.cpp).
//
// Build with -DAESLIB_BUILD_FUZZERS=ON (Clang required). See README.md.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "aeslib/aes_gcm.hpp"
#include "aeslib/exceptions.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::vector<std::byte> bytes(size);
    for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<std::byte>(data[i]);

    try {
        aeslib::deserialize_gcm(bytes);
    } catch (const aeslib::FormatError&) {
        // Expected: malformed input correctly rejected.
    }
    return 0;
}
