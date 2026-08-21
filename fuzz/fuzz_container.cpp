// libFuzzer harness for aeslib::deserialize() (include/aeslib/container.hpp)
// — the parser for the CTR container's on-disk format, which is fully
// attacker-controlled input whenever a caller loads a ciphertext file from
// disk. Manual review of src/container.cpp already confirmed the length
// field (ct_len) is checked against the actual remaining byte count before
// use, not trusted for allocation sizing (see DESIGN.md) — this harness is
// regression-prevention over the wider input space (structural truncation at
// every offset, integer edge cases), not a response to a found bug.
//
// Build with -DAESLIB_BUILD_FUZZERS=ON (Clang required). See README.md.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "aeslib/container.hpp"
#include "aeslib/exceptions.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::vector<std::byte> bytes(size);
    for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<std::byte>(data[i]);

    try {
        aeslib::deserialize(bytes);
    } catch (const aeslib::FormatError&) {
        // Expected: malformed input correctly rejected.
    }
    return 0;
}
