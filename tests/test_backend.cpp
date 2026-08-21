// The CI hook: when AESLIB_EXPECTED_BACKEND is set to "hardware" or
// "software", asserts active_backend() matches. Left unset, this test is a
// no-op skip. This observes the runtime CPUID/HWCAP/hwprobe-based dispatch
// decision (plus the hardware self-verification layered on top of it, see
// cpu_detect.cpp) without itself influencing it. See the CI workflow's
// qemu-aes-on / qemu-aes-off jobs, which set this to pin down which backend a
// given run is expected to land on.
//
// AESLIB_FORCE_SOFTWARE (tested below) is the one env var that *does*
// override dispatch — deliberately software-only, see active_backend()'s
// comment for why forcing the hardware path is never offered.

#include <cstdlib>
#include <cstring>
#include <string>

#include "aeslib/backend.hpp"
#include "aeslib/key.hpp"
#include "src/internal.hpp"
#include "src/kat_vector.hpp"
#include "test_support.hpp"

#if defined(_WIN32)
namespace {
void set_env(const char* name, const char* value) { _putenv_s(name, value); }
void clear_env(const char* name) { _putenv_s(name, ""); }
} // namespace
#else
namespace {
void set_env(const char* name, const char* value) { setenv(name, value, 1); }
void clear_env(const char* name) { unsetenv(name); }
} // namespace
#endif

AESLIB_TEST(backend, matches_expected_backend_if_set) {
    const char* expected = std::getenv("AESLIB_EXPECTED_BACKEND");
    if (expected == nullptr || std::strlen(expected) == 0) {
        std::printf("   (skipped: AESLIB_EXPECTED_BACKEND not set)\n");
        return;
    }

    const aeslib::Backend actual = aeslib::active_backend();
    if (std::strcmp(expected, "hardware") == 0) {
        CHECK(actual == aeslib::Backend::Hardware);
    } else if (std::strcmp(expected, "software") == 0) {
        CHECK(actual == aeslib::Backend::Software);
    } else {
        aeslib::test::report_failure(__FILE__, __LINE__,
                                      std::string("unrecognized AESLIB_EXPECTED_BACKEND value: ") + expected);
    }
}

AESLIB_TEST(backend, force_software_overrides_hardware) {
    set_env("AESLIB_FORCE_SOFTWARE", "1");
    const aeslib::Backend actual = aeslib::active_backend();
    clear_env("AESLIB_FORCE_SOFTWARE");
    CHECK(actual == aeslib::Backend::Software);
}

AESLIB_TEST(backend, hardware_self_test_rejects_wrong_kat) {
    if (!aeslib::cpu::has_hw_aes()) {
        std::printf("   (skipped: no hardware AES acceleration on this machine)\n");
        return;
    }

    using aeslib::detail::Block;
    auto to_block = [](const unsigned char (&bytes)[16]) {
        Block block{};
        for (std::size_t i = 0; i < 16; ++i) block[i] = static_cast<std::byte>(bytes[i]);
        return block;
    };

    const aeslib::SecretKey key = aeslib::detail::key_from_bytes(
        reinterpret_cast<const std::byte*>(aeslib::detail::kKat256Key), aeslib::KeySize::Aes256);
    const Block plaintext = to_block(aeslib::detail::kKat256Plaintext);
    const Block correct = to_block(aeslib::detail::kKat256Ciphertext);
    Block wrong = correct;
    wrong[0] ^= std::byte{0xff}; // deliberately wrong "expected" ciphertext

    // The real hardware path (verified correct by every other test in this
    // suite) genuinely produces `correct`, not `wrong` — so this proves
    // kat_matches() actually rejects a hardware answer that disagrees with
    // the expected vector, the failure mode the self-test exists to catch,
    // without needing hardware that's actually broken.
    CHECK(aeslib::detail::kat_matches(aeslib::detail::aes256_encrypt_block_hw, key, plaintext, correct));
    CHECK(!aeslib::detail::kat_matches(aeslib::detail::aes256_encrypt_block_hw, key, plaintext, wrong));
}
