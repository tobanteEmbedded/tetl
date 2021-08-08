cmake_minimum_required(VERSION 3.8)
project(etl LANGUAGES CXX)

option(TETL_BUILD_CPP20     "Build with C++20. Default is C++17" ON)
option(TETL_BUILD_CPP23     "Build with C++23. Default is C++17" OFF)
option(TETL_BUILD_EXAMPLES  "Build examples" ON)
option(TETL_BUILD_TESTS     "Build unit tests" ON)
option(TETL_BUILD_WERROR    "Build with all warnings as errors" OFF)
option(TETL_BUILD_ASAN      "Build with address sanitizer enabled" OFF)
option(TETL_BUILD_UBSAN     "Build with undefined behavior sanitizer enabled" OFF)
option(TETL_BUILD_MSAN      "Build with memory sanitizer enabled" OFF)
option(TETL_BUILD_TSAN      "Build with thread sanitizer enabled" OFF)
option(TETL_BUILD_COVERAGE  "Build with coverage reporting for gcc/clang" OFF)

# Only do these if this is the main project,
# and not if it is included through add_subdirectory.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(TETL_BUILD_CPP23)
      set(CMAKE_CXX_STANDARD 23 CACHE STRING "C++ standard to conform to")
    elseif(TETL_BUILD_CPP20)
      set(CMAKE_CXX_STANDARD 20 CACHE STRING "C++ standard to conform to")
    else()
      set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to conform to")
    endif()

    set(CMAKE_CXX_STANDARD_REQUIRED YES)
    set(CMAKE_CXX_EXTENSIONS NO)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(BUILD_SHARED_LIBS OFF)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CodeCoverage)
include(CompilerOptions)
include(CompilerWarnings)

add_library(${PROJECT_NAME} INTERFACE)
add_library(tobanteEmbedded::etl ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR})

if(NOT CMAKE_CROSSCOMPILING)
  if(TETL_BUILD_TESTS)
      add_subdirectory(3rd_party/Catch2 EXCLUDE_FROM_ALL)
      list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rd_party/Catch2/extras")
      include(CTest)
      include(Catch)
      add_subdirectory(tests)
  endif()

  if(TETL_BUILD_EXAMPLES)
    add_subdirectory(examples)
  endif()
endif(NOT CMAKE_CROSSCOMPILING)

