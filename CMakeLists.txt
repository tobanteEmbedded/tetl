cmake_minimum_required(VERSION 3.8)
project(taetl LANGUAGES CXX)

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
option(TOBANTEAUDIO_ETL_BUILD_DOCS      "Build documentation" ON)
option(TOBANTEAUDIO_ETL_ENABLE_COVERAGE "Enable coverage reporting for gcc/clang" FALSE)
option(TOBANTEAUDIO_ETL_ENABLE_TIDY     "Run clang-tidy at compile time" OFF)

# Cmake setup
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)
include(CodeCoverage)
include(BuildDoxygen)

# tidy, has to be enabled for each target.
if(TOBANTEAUDIO_ETL_ENABLE_TIDY)
  if(CMake_SOURCE_DIR STREQUAL CMake_BINARY_DIR)
    message(FATAL_ERROR "TOBANTEAUDIO_ETL_ENABLE_TIDY requires an out-of-source build!")
  endif()

  find_program(CLANG_TIDY_EXE NAMES clang-tidy)
  if(NOT CLANG_TIDY_EXE)
    message(WARNING "TOBANTEAUDIO_ETL_ENABLE_TIDY is ON but clang-tidy is not found!")
    set(DO_CLANG_TIDY "")
  else()
    set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}")
  endif()
  
  # Create a preprocessor definition that depends on .clang-tidy content so
  # the compile command will change when .clang-tidy changes.  This ensures
  # that a subsequent build re-runs clang-tidy on all sources even if they
  # do not otherwise need to be recompiled.  Nothing actually uses this
  # definition.  We add it to targets on which we run clang-tidy just to
  # get the build dependency on the .clang-tidy file.
  file(SHA1 ${CMAKE_CURRENT_SOURCE_DIR}/.clang-tidy clang_tidy_sha1)
  set(CLANG_TIDY_DEFINITIONS "CLANG_TIDY_SHA1=${clang_tidy_sha1}")
  unset(clang_tidy_sha1)
endif(TOBANTEAUDIO_ETL_ENABLE_TIDY)
configure_file(.clang-tidy .clang-tidy COPYONLY)


if(TOBANTEAUDIO_ETL_BUILD_DOCS)
  buildDocs()
endif()

# Main Project
add_library(${PROJECT_NAME} INTERFACE)
add_library(tobanteAudio::etl ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR})

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

