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

  # Rather than relying on CMake's default absolute build-tree rpath (which
  # only resolves on the machine that built it), point at $ORIGIN/@loader_path
  # so the test binary finds libaeslib_c next to itself wherever it's run
  # from — e.g. after being downloaded as a CI artifact onto a different
  # runner for the qemu-aes-on/off jobs. No effect on Windows, where DLL
  # search already includes the executable's own directory by default.
  if(NOT MSVC)
    set_target_properties(aeslib_tests PROPERTIES
      BUILD_RPATH_USE_ORIGIN ON
      INSTALL_RPATH_USE_LINK_PATH TRUE
    )
    if(APPLE)
      set_target_properties(aeslib_tests PROPERTIES BUILD_RPATH "@loader_path")
    else()
      set_target_properties(aeslib_tests PROPERTIES BUILD_RPATH "$ORIGIN")
    endif()
  endif()
endif()

foreach(suite ${AESLIB_TEST_SUITES})
  add_test(NAME aeslib.${suite} COMMAND aeslib_tests ${suite})
endforeach()
