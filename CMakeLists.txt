cmake_minimum_required(VERSION 3.28)
project(tetl-dev LANGUAGES CXX)

option(TETL_BUILD_CONTRACT_CHECKS      "Build with contract assertions"                  ON)
option(TETL_BUILD_CONTRACT_CHECKS_SAFE "Build with all/slow contract assertions"         OFF)
option(TETL_BUILD_COVERAGE             "Build with coverage reporting for gcc/clang"     OFF)
option(TETL_BUILD_CXX_MODULES          "Build with C++20 modules"                        OFF)
option(TETL_BUILD_WERROR               "Build with all warnings as errors"               OFF)
option(TETL_BUILD_WEVERYTHING          "Build with -Weverything (clang only)"            OFF)

find_program(CCACHE ccache)
if(CCACHE)
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(code_coverage)
include(compiler_warnings)

add_subdirectory(include)

if(TETL_BUILD_CXX_MODULES)
    add_subdirectory(module)
endif()

enable_testing()
add_subdirectory(tests)
add_subdirectory(examples)
