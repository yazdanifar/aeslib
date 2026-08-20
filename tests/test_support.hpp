#pragma once

// Minimal assertion + suite-registration helpers. Deliberately hand-rolled
// rather than pulling in a framework (see DESIGN.md) — this library has no
// third-party dependencies anywhere, and the test binary keeps that
// property.

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace aeslib::test {

inline int& failure_count() {
    static int count = 0;
    return count;
}

inline void report_failure(const char* file, int line, const std::string& message) {
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, message.c_str());
    ++failure_count();
}

struct Case {
    std::string suite;
    std::string name;
    std::function<void()> run;
};

// Registration order == declaration order, which matters for readable
// output; a map would silently alphabetize.
inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

struct Registrar {
    Registrar(std::string suite, std::string name, std::function<void()> fn) {
        registry().push_back(Case{std::move(suite), std::move(name), std::move(fn)});
    }
};

} // namespace aeslib::test

#define AESLIB_TEST(suite, name)                                                    \
    static void suite##_##name();                                                  \
    static ::aeslib::test::Registrar aeslib_registrar_##suite##_##name(              \
        #suite, #name, [] { suite##_##name(); });                                   \
    static void suite##_##name()

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            ::aeslib::test::report_failure(__FILE__, __LINE__, "CHECK failed: " #cond); \
        }                                                                               \
    } while (0)

#define CHECK_EQ(a, b)                                                                              \
    do {                                                                                            \
        if (!((a) == (b))) {                                                                        \
            ::aeslib::test::report_failure(__FILE__, __LINE__, "CHECK_EQ failed: " #a " != " #b);   \
        }                                                                                           \
    } while (0)

#define CHECK_THROWS(expr, exc_type)                                                                     \
    do {                                                                                                  \
        bool threw = false;                                                                               \
        try {                                                                                              \
            (void)(expr);                                                                                  \
        } catch (const exc_type&) {                                                                        \
            threw = true;                                                                                  \
        } catch (...) {                                                                                    \
            ::aeslib::test::report_failure(__FILE__, __LINE__,                                              \
                                            "CHECK_THROWS: wrong exception type from: " #expr);             \
            threw = true;                                                                                  \
        }                                                                                                  \
        if (!threw) {                                                                                      \
            ::aeslib::test::report_failure(__FILE__, __LINE__, "CHECK_THROWS: no exception from: " #expr); \
        }                                                                                                  \
    } while (0)
