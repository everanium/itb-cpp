# CMakeLists.txt — minimal CMake skeleton for the ITB C++ binding.
#
# The C++ binding is header-only: this file declares an INTERFACE
# library so consumers can `target_link_libraries(my_app PRIVATE itb)`
# and pick up the include path + transitive link to the C binding's
# static archive plus libitb.so.
#
# The Makefile in this directory is the primary build driver for tests
# and benches (mirroring the C binding's POSIX-portable convention).
# This CMake file exists for downstream packaging (vcpkg / conan /
# system installs) and is intentionally light.

cmake_minimum_required(VERSION 3.20)
project(itb_cpp VERSION 0.1.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- INTERFACE library ----------------------------------------------
add_library(itb INTERFACE)
target_include_directories(itb INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../c/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(itb INTERFACE cxx_std_17)

# ---- Header drift gate ----------------------------------------------
add_custom_target(check_header
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_header.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Verifying include/itb.h is in sync with bindings/c/include/itb.h"
)

# ---- Tests + bench (deferred — fleshed out in Phase 7.5 / Phase 9) ---
option(ITB_CPP_BUILD_TESTS "Build the C++ binding tests" OFF)
option(ITB_CPP_BUILD_BENCH "Build the C++ binding benches" OFF)
