cmake_minimum_required(VERSION 3.8)
project(etl LANGUAGES CXX)

# Only do these if this is the main project, 
# and not if it is included through add_subdirectory.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Standard
    set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to conform to")
    set(CMAKE_CXX_STANDARD_REQUIRED YES)
    set(CMAKE_CXX_EXTENSIONS NO)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(BUILD_SHARED_LIBS OFF)
    # Let's nicely support folders in IDE's
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

# Options
option(TOBANTEAUDIO_ETL_BUILD_EXAMPLES  "Build examples" ON)
option(TOBANTEAUDIO_ETL_BUILD_TESTS     "Build unit tests" ON)
option(TOBANTEAUDIO_ETL_BUILD_DOCS      "Build documentation" OFF)
option(TOBANTEAUDIO_ETL_BUILD_ASAN      "Build with address sanitizer enabled" OFF)
option(TOBANTEAUDIO_ETL_BUILD_UBSAN     "Build with undefined behavior sanitizer enabled" OFF)
option(TOBANTEAUDIO_ETL_BUILD_MSAN      "Build with memory sanitizer enabled" OFF)
option(TOBANTEAUDIO_ETL_BUILD_TSAN      "Build with thread sanitizer enabled" OFF)
option(TOBANTEAUDIO_ETL_ENABLE_COVERAGE "Enable coverage reporting for gcc/clang" FALSE)

# Cmake setup
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)
include(CodeCoverage)
include(CompilerOptions)

# Main Project
add_library(${PROJECT_NAME} INTERFACE)
add_library(tobanteAudio::etl ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR})

if(NOT CMAKE_CROSSCOMPILING)
  if(TOBANTEAUDIO_ETL_BUILD_DOCS)
    include(BuildDoxygen)
    buildDocs()
  endif()

  # Testing
  if(TOBANTEAUDIO_ETL_BUILD_TESTS)
      list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rd_party/Catch2/contrib")
      enable_testing()
      add_subdirectory(3rd_party/Catch2 ${CMAKE_CURRENT_BINARY_DIR}/3rd_party/Catch2 EXCLUDE_FROM_ALL)
      include(CTest)
      include(Catch)
      add_subdirectory(tests)
  endif()

  # Examples
  if(TOBANTEAUDIO_ETL_BUILD_EXAMPLES)
    add_subdirectory(examples)
  endif()
endif(NOT CMAKE_CROSSCOMPILING)

