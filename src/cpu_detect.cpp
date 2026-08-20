#include "internal.hpp"

#include "aeslib/backend.hpp"

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#define AESLIB_X86 1
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define AESLIB_X86 1
#else
#define AESLIB_X86 0
#endif

namespace aeslib::cpu {

bool has_aes_ni() {
#if AESLIB_X86
    static const bool supported = [] {
        int regs[4] = {0, 0, 0, 0};
#if defined(_MSC_VER)
        __cpuid(regs, 1);
#else
        __cpuid(1, regs[0], regs[1], regs[2], regs[3]);
#endif
        constexpr int kAesNiEcxBit = 25;
        return (regs[2] & (1 << kAesNiEcxBit)) != 0;
    }();
    return supported;
#else
    return false;
#endif
}

} // namespace aeslib::cpu

namespace aeslib {

Backend active_backend() {
    return cpu::has_aes_ni() ? Backend::Hardware : Backend::Software;
}

} // namespace aeslib
