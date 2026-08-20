cmake_minimum_required(VERSION 3.16)
project(aeslib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_library(aeslib STATIC
  src/aes256_ctr.cpp
  src/aes_core_soft.cpp
  src/aes_core_ni.cpp
  src/cpu_detect.cpp
  src/csprng.cpp
  src/key.cpp
  src/key_storage.cpp
  src/sha256.cpp
  src/container.cpp
)

target_include_directories(aeslib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(aeslib PUBLIC cxx_std_17)

set(AESLIB_TARGET_IS_X86 FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|i.86)$")
  set(AESLIB_TARGET_IS_X86 TRUE)
endif()

if(MSVC)
  target_compile_options(aeslib PRIVATE /W4)
else()
  target_compile_options(aeslib PRIVATE -Wall -Wextra)
  if(AESLIB_TARGET_IS_X86)
    # AES-NI intrinsics are only used in aes_core_ni.cpp; scoping -maes to
    # this one translation unit keeps the rest of the binary free of any
    # architecture-specific baked-in instructions, which is what makes
    # runtime dispatch (see cpu_detect.cpp) actually portable across
    # machines.
    set_source_files_properties(src/aes_core_ni.cpp PROPERTIES COMPILE_OPTIONS "-maes")
  endif()
endif()

if(WIN32)
  target_link_libraries(aeslib PRIVATE bcrypt)
endif()

# Reviewers are told this will be checked under sanitizers (brief 2.9); one
# flag opts both the library and the tests in rather than requiring a
# separate sanitizer build script.
option(AESLIB_ENABLE_SANITIZERS "Build with -fsanitize=address,undefined" OFF)
if(AESLIB_ENABLE_SANITIZERS)
  if(MSVC)
    message(WARNING "AESLIB_ENABLE_SANITIZERS has no effect with MSVC; use /fsanitize=address instead.")
  else()
    target_compile_options(aeslib PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(aeslib PUBLIC -fsanitize=address,undefined)
  endif()
endif()

add_executable(aes_harness main.cpp)
target_link_libraries(aes_harness PRIVATE aeslib)

option(AESLIB_BUILD_TESTS "Build the aeslib_tests suite" ON)
if(AESLIB_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
