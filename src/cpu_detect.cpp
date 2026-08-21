#include "internal.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "aeslib/backend.hpp"
#include "kat_vector.hpp"

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

namespace aeslib::detail {

bool kat_matches(Block (*hw_encrypt)(const SecretKey&, const Block&), const SecretKey& key,
                  const Block& plaintext, const Block& expected) {
    return hw_encrypt(key, plaintext) == expected;
}

} // namespace aeslib::detail

namespace aeslib::cpu {

namespace {

// Converts a 16-byte KAT array into a Block, mirroring the same helper
// duplicated across tests/test_aes_core.cpp — kept separate here since this
// one runs in production code, not test code, and the two shouldn't share a
// build target.
detail::Block kat_block(const unsigned char (&bytes)[16]) {
    detail::Block block{};
    for (std::size_t i = 0; i < 16; ++i) block[i] = static_cast<std::byte>(bytes[i]);
    return block;
}

// Runs one AES-128 and one AES-256 FIPS-197 known-answer encryption through
// the arch's hardware backend and checks the output. This is deliberately
// *not* a second capability-detection mechanism — CPUID/HWCAP/hwprobe above
// already decided the instruction is present. It's a functional check on top
// of that: a security team's threat model includes hosts that misreport CPU
// capability (a buggy hypervisor/emulator exposing a feature bit for an
// instruction it doesn't actually execute correctly, or a silicon erratum),
// and trusting the feature bit alone means silently producing wrong
// ciphertext on such a host instead of falling back to the always-correct
// software path. Only ever called with the raw capability check already
// true (see has_hw_aes() below), so calling the _hw functions here is safe.
//
// What this does *not* protect against: a hardware bug that only manifests
// on inputs other than these two fixed KAT vectors — it's a spot check, not
// exhaustive verification. See DESIGN.md.
bool hw_backend_passes_self_test() {
    const SecretKey key128 = detail::key_from_bytes(
        reinterpret_cast<const std::byte*>(detail::kKat128Key), KeySize::Aes128);
    const detail::Block pt128 = kat_block(detail::kKat128Plaintext);
    const detail::Block expected128 = kat_block(detail::kKat128Ciphertext);
    if (!detail::kat_matches(detail::aes128_encrypt_block_hw, key128, pt128, expected128)) return false;

    const SecretKey key256 = detail::key_from_bytes(
        reinterpret_cast<const std::byte*>(detail::kKat256Key), KeySize::Aes256);
    const detail::Block pt256 = kat_block(detail::kKat256Plaintext);
    const detail::Block expected256 = kat_block(detail::kKat256Ciphertext);
    return detail::kat_matches(detail::aes256_encrypt_block_hw, key256, pt256, expected256);
}

} // namespace

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
        return (regs[2] & (1 << kAesNiEcxBit)) != 0 && hw_backend_passes_self_test();
    }();
    return supported;
#elif AESLIB_ARM_LINUX
    static const bool supported =
        (getauxval(AT_HWCAP) & HWCAP_AES) != 0 && hw_backend_passes_self_test();
    return supported;
#elif AESLIB_ARM_APPLE
    static const bool supported = [] {
        int value = 0;
        std::size_t size = sizeof(value);
        return sysctlbyname("hw.optional.arm.FEAT_AES", &value, &size, nullptr, 0) == 0 && value == 1 &&
               hw_backend_passes_self_test();
    }();
    return supported;
#elif AESLIB_ARM_WINDOWS
    static const bool supported =
        IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0 && hw_backend_passes_self_test();
    return supported;
#elif AESLIB_RISCV64_LINUX
    static const bool supported = [] {
        struct riscv_hwprobe probe;
        probe.key = RISCV_HWPROBE_KEY_IMA_EXT_0;
        probe.value = 0;
        if (syscall(SYS_riscv_hwprobe, &probe, 1, 0, nullptr, 0) != 0) return false;
        if ((static_cast<std::uint64_t>(probe.value) & RISCV_HWPROBE_EXT_ZKNE) == 0) return false;
        return hw_backend_passes_self_test();
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
    // Testing-only escape hatch to exercise the software path on a
    // hardware-capable machine (e.g. CI). Deliberately one-directional: it
    // can only downgrade Hardware -> Software, never force Software ->
    // Hardware, since the latter would call real hardware AES instructions
    // on a CPU that may not actually support them and fault. See DESIGN.md.
    // std::getenv is fine here: single-threaded read of a testing-only
    // variable at process start, well before any std::setenv could race it.
    // MSVC's _dupenv_s alternative would need heap allocation for no benefit.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    const char* force_software = std::getenv("AESLIB_FORCE_SOFTWARE");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (force_software != nullptr && std::strcmp(force_software, "") != 0 && std::strcmp(force_software, "0") != 0) {
        return Backend::Software;
    }
    return cpu::has_hw_aes() ? Backend::Hardware : Backend::Software;
}

} // namespace aeslib
