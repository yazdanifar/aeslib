add_executable(aeslib_tests
  test_main.cpp
  test_aes_core.cpp
  test_ctr.cpp
  test_container.cpp
  test_key.cpp
  test_key_storage.cpp
  test_backend.cpp
  test_reference_vectors.cpp
  test_gcm.cpp
  test_generic.cpp
)

target_link_libraries(aeslib_tests PRIVATE aeslib)
# Tests reach library internals (src/internal.hpp) directly rather than
# through the public API, so the test binary needs the repo root on its
# include path too.
target_include_directories(aeslib_tests PRIVATE ${CMAKE_SOURCE_DIR})

if(MSVC)
  target_compile_options(aeslib_tests PRIVATE /W4)
else()
  target_compile_options(aeslib_tests PRIVATE -Wall -Wextra)
endif()

# One add_test() per suite, all against the same binary (see test_main.cpp's
# suite-name filtering) — this is what lets CTest report each suite
# separately while keeping a single zero-dependency test executable.
set(AESLIB_TEST_SUITES aes_core ctr container key key_storage backend reference_vectors gcm generic)

# The C ABI (include/aeslib/capi.h) is only built when AESLIB_BUILD_C_API is
# on, so its test suite only exists then too — aeslib_tests links directly
# against the aeslib_c shared library it calls into.
if(TARGET aeslib_c)
  target_sources(aeslib_tests PRIVATE test_capi.cpp)
  target_link_libraries(aeslib_tests PRIVATE aeslib_c)
  list(APPEND AESLIB_TEST_SUITES capi)
endif()

foreach(suite ${AESLIB_TEST_SUITES})
  add_test(NAME aeslib.${suite} COMMAND aeslib_tests ${suite})
endforeach()
