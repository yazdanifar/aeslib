#pragma once

#include <stdexcept>
#include <string>

namespace aeslib {

// Thrown for filesystem/OS-level failures (missing file, permission denied,
// short read/write, RNG source unavailable).
class IoError : public std::runtime_error {
public:
    explicit IoError(const std::string& message) : std::runtime_error(message) {}
};

// Thrown when a stored container/key file is malformed or has an
// unsupported version marker.
class FormatError : public std::runtime_error {
public:
    explicit FormatError(const std::string& message) : std::runtime_error(message) {}
};

// Thrown when an operation is asked to process more data than this library's
// format can represent (currently: a single Aes256Ctr call larger than the
// 32-bit block counter's range — see DESIGN.md's nonce/IV strategy section).
class LimitError : public std::runtime_error {
public:
    explicit LimitError(const std::string& message) : std::runtime_error(message) {}
};

} // namespace aeslib
