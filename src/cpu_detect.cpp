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

#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#define AESLIB_ARM_LINUX 1
#else
#define AESLIB_ARM_LINUX 0
#endif

#if defined(__aarch64__) && defined(__APPLE__)
#include <cstddef>
#include <sys/sysctl.h>
#define AESLIB_ARM_APPLE 1
#else
#define AESLIB_ARM_APPLE 0
#endif

#if defined(_M_ARM64)
#include <windows.h>
#define AESLIB_ARM_WINDOWS 1
#else
#define AESLIB_ARM_WINDOWS 0
#endif

namespace aeslib::cpu {

bool has_hw_aes() {
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
#elif AESLIB_ARM_LINUX
    static const bool supported = (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
    return supported;
#elif AESLIB_ARM_APPLE
    static const bool supported = [] {
        int value = 0;
        std::size_t size = sizeof(value);
        return sysctlbyname("hw.optional.arm.FEAT_AES", &value, &size, nullptr, 0) == 0 && value == 1;
    }();
    return supported;
#elif AESLIB_ARM_WINDOWS
    static const bool supported = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
    return supported;
#else
    // No known hardware-AES detection mechanism for this architecture/OS
    // combination — fall back to the software path, which is always
    // correct, just not accelerated.
    return false;
#endif
}

} // namespace aeslib::cpu

namespace aeslib {

Backend active_backend() {
    return cpu::has_hw_aes() ? Backend::Hardware : Backend::Software;
}

} // namespace aeslib
