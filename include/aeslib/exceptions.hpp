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

} // namespace aeslib
