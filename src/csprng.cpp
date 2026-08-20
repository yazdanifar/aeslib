#include "internal.hpp"

#include "aeslib/exceptions.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <cerrno>
#include <cstring>
#include <string>
#include <sys/random.h>
#else
// Generic POSIX fallback (e.g. macOS, BSD): arc4random_buf is a CSPRNG
// seeded and reseeded by the kernel, no file descriptor to manage.
#include <cstdlib>
#endif

namespace aeslib::rng {

#if defined(_WIN32)

void fill_random(std::byte* buffer, std::size_t size) {
    NTSTATUS status = BCryptGenRandom(
        nullptr, reinterpret_cast<PUCHAR>(buffer), static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0 /* STATUS_SUCCESS */) {
        throw IoError("BCryptGenRandom failed");
    }
}

#elif defined(__linux__)

void fill_random(std::byte* buffer, std::size_t size) {
    std::size_t filled = 0;
    while (filled < size) {
        ssize_t n = getrandom(buffer + filled, size - filled, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw IoError(std::string("getrandom failed: ") + std::strerror(errno));
        }
        filled += static_cast<std::size_t>(n);
    }
}

#else

void fill_random(std::byte* buffer, std::size_t size) {
    arc4random_buf(buffer, size);
}

#endif

} // namespace aeslib::rng
