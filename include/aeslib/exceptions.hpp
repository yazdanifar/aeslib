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

// Thrown when an operation is asked to do something outside the bounds this
// library considers safe or meaningful — either more data than the format
// can represent (a single Aes256Ctr call larger than the 32-bit block
// counter's range — see DESIGN.md's nonce/IV strategy section), or a
// parameter that would silently defeat the operation's purpose (e.g. a
// PBKDF2 iteration count of zero).
class LimitError : public std::runtime_error {
public:
    explicit LimitError(const std::string& message) : std::runtime_error(message) {}
};

// Thrown when a passphrase-protected key file's HMAC tag doesn't verify —
// either the wrong passphrase was used to decrypt, or the file has been
// corrupted/tampered with. Kept separate from FormatError (structural
// parse failure) so callers can distinguish "ask for the passphrase again"
// from "file is unreadable".
class AuthenticationError : public std::runtime_error {
public:
    explicit AuthenticationError(const std::string& message) : std::runtime_error(message) {}
};

} // namespace aeslib
