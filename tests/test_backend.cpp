// The CI hook: when AESLIB_EXPECTED_BACKEND is set to "hardware" or
// "software", asserts active_backend() matches. Left unset, this test is a
// no-op skip. This is deliberately the *only* place the test suite reads an
// environment variable to influence an assertion — it observes the runtime
// CPUID-based dispatch decision, it never overrides it, so what's under test
// (cpu_detect.cpp) is never bypassed. See the CI workflow's qemu-aes-on /
// qemu-aes-off jobs, which set this to pin down which backend a given run is
// expected to land on.

#include <cstdlib>
#include <cstring>
#include <string>

#include "aeslib/backend.hpp"
#include "test_support.hpp"

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
