cmake_minimum_required(VERSION 3.19)
project(tetl-dev LANGUAGES CXX)

option(TETL_BUILD_MODULE      "Build as C++20 module (eperimental)" OFF)
option(TETL_BUILD_WERROR      "Build with all warnings as errors" OFF)
option(TETL_BUILD_ASAN        "Build with address sanitizer enabled" OFF)
option(TETL_BUILD_UBSAN       "Build with undefined behavior sanitizer enabled" OFF)
option(TETL_BUILD_MSAN        "Build with memory sanitizer enabled" OFF)
option(TETL_BUILD_TSAN        "Build with thread sanitizer enabled" OFF)
option(TETL_BUILD_COVERAGE    "Build with coverage reporting for gcc/clang" OFF)
option(TETL_BUILD_WEVERYTHING "Build with -Weverything (clang only)" OFF)
option(TETL_BUILD_TIMETRACE   "Build with -ftime-trace (clang only)" OFF)

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

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(include)
add_subdirectory(src)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(code_coverage)
include(compiler_options)
include(compiler_warnings)

include(CTest)
add_subdirectory(tests)
add_subdirectory(examples)
