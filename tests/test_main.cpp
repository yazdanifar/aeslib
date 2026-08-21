// Test binary entry point. With no arguments, runs every registered case.
// With one argument, runs only cases whose suite matches it — this is what
// lets CTest register one add_test() per suite against a single binary.

#include <cstdio>
#include <cstdlib>
#include <string>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "test_support.hpp"

int main(int argc, char** argv) {
#if defined(_WIN32)
    // Without this, a crash (e.g. an illegal-instruction fault from a CPU
    // that misreports a capability) pops a blocking Windows Error Reporting
    // dialog instead of exiting — headless CI has no one to click it, so the
    // process (and the whole pipeline) hangs until the job's timeout kills
    // it. Fail fast with a nonzero exit code instead.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#endif
    const std::string suite_filter = argc > 1 ? argv[1] : "";

    int ran = 0;
    for (const auto& test_case : aeslib::test::registry()) {
        if (!suite_filter.empty() && test_case.suite != suite_filter) {
            continue;
        }
        std::printf(" - %s.%s\n", test_case.suite.c_str(), test_case.name.c_str());
        test_case.run();
        ++ran;
    }

    if (ran == 0) {
        std::fprintf(stderr, "no tests matched suite filter '%s'\n", suite_filter.c_str());
        return EXIT_FAILURE;
    }

    const int failures = aeslib::test::failure_count();
    if (failures > 0) {
        std::fprintf(stderr, "%d test(s) ran, %d assertion failure(s)\n", ran, failures);
        return EXIT_FAILURE;
    }
    std::printf("%d test(s) passed.\n", ran);
    return EXIT_SUCCESS;
}
