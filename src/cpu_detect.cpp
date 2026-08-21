#include "internal.hpp"

#include <cstdint>

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

// Linux riscv64 detection goes through the riscv_hwprobe() syscall rather
// than getauxval(AT_HWCAP): HWCAP only has bits for base ISA letters, not
// sub-extensions like Zkne. Used via the raw syscall (kernel UAPI
// <asm/hwprobe.h> struct/macros, invoked with syscall(2)) rather than
// glibc's <sys/hwprobe.h> wrapper, since that wrapper only landed in glibc
// 2.39 — the raw syscall interface has been stable since Linux 6.4 and
// works against any glibc version. Only the Zkne bit is checked — Zknd
// (decryption) is never used, see aes_core_riscv.cpp/CMakeLists.txt.
#if defined(__riscv) && __riscv_xlen == 64 && defined(__linux__)
#include <asm/hwprobe.h>
#include <sys/syscall.h>
#include <unistd.h>
#define AESLIB_RISCV64_LINUX 1
#ifndef SYS_riscv_hwprobe
#define SYS_riscv_hwprobe 258
#endif
#ifndef RISCV_HWPROBE_KEY_IMA_EXT_0
#define RISCV_HWPROBE_KEY_IMA_EXT_0 4
#endif
#ifndef RISCV_HWPROBE_EXT_ZKNE
#define RISCV_HWPROBE_EXT_ZKNE (1ULL << 12)
#endif
#else
#define AESLIB_RISCV64_LINUX 0
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
#elif AESLIB_RISCV64_LINUX
    static const bool supported = [] {
        struct riscv_hwprobe probe;
        probe.key = RISCV_HWPROBE_KEY_IMA_EXT_0;
        probe.value = 0;
        if (syscall(SYS_riscv_hwprobe, &probe, 1, 0, nullptr, 0) != 0) return false;
        return (static_cast<std::uint64_t>(probe.value) & RISCV_HWPROBE_EXT_ZKNE) != 0;
    }();
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
