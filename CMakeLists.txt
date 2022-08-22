cmake_minimum_required(VERSION 3.19)
project(etl LANGUAGES CXX)

option(TETL_BUILD_EXAMPLES    "Build examples" ON)
option(TETL_BUILD_TESTS       "Build unit tests" ON)
option(TETL_BUILD_WERROR      "Build with all warnings as errors" OFF)
option(TETL_BUILD_ASAN        "Build with address sanitizer enabled" OFF)
option(TETL_BUILD_UBSAN       "Build with undefined behavior sanitizer enabled" OFF)
option(TETL_BUILD_MSAN        "Build with memory sanitizer enabled" OFF)
option(TETL_BUILD_TSAN        "Build with thread sanitizer enabled" OFF)
option(TETL_BUILD_COVERAGE    "Build with coverage reporting for gcc/clang" OFF)
option(TETL_BUILD_WEVERYTHING "Build with -Weverything (clang only)" OFF)
option(TETL_BUILD_TIMETRACE   "Build with -ftime-trace (clang only)" OFF)

# Only do these if this is the main project,
# and not if it is included through add_subdirectory.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # find_program(CCACHE ccache)
    # if(CCACHE)
    #     set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
    # endif()

    if(NOT "${CMAKE_CXX_STANDARD}")
      set(CMAKE_CXX_STANDARD 17)
    endif()

    set(CMAKE_CXX_STANDARD_REQUIRED YES)
    set(CMAKE_CXX_EXTENSIONS NO)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(BUILD_SHARED_LIBS OFF)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(code_coverage)
include(compiler_options)
include(compiler_warnings)

add_library(${PROJECT_NAME} INTERFACE)
add_library(tetl::etl ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR})

if(TETL_BUILD_TESTS)
    include(CTest)
    add_subdirectory(tests)
endif()

if(TETL_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
