# Cross-compilation toolchain for the CI job that builds and runs this
# library on aarch64 under QEMU (see .github/workflows/ci.yml). Not needed
# for a native build on any platform — only for deliberately targeting a
# different architecture than the host.
#
# Usage: cmake -B build-aarch64 -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-linux-gnu.cmake
# Requires the aarch64-linux-gnu-{gcc,g++} cross toolchain package to be
# installed (e.g. `apt-get install g++-aarch64-linux-gnu` on Debian/Ubuntu).

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
