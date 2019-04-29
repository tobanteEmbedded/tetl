cmake_minimum_required(VERSION 3.8)

# Cmake setup
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)
include(BuildDoxygen)

# Project
project(taetl)

# Options
option(TOBANTEAUDIO_ETL_BUILD_EXAMPLES "Build examples" ON)
option(TOBANTEAUDIO_ETL_BUILD_TESTS    "Build unit tests" ON)
option(TOBANTEAUDIO_ETL_BUILD_DOCS     "Build documentation" ON)

# Coverage
if(CMAKE_COMPILER_IS_GNUCC)
  option(TOBANTEAUDIO_ETL_ENABLE_COVERAGE "Enable coverage reporting for gcc/clang" FALSE)
  if(TOBANTEAUDIO_ETL_ENABLE_COVERAGE)
    add_compile_options(--coverage -O0)
  endif()
endif()

# Main Project
add_subdirectory(src)

# Documentation (doxygen)
if(TOBANTEAUDIO_ETL_BUILD_DOCS)
  buildDocs()
endif()

# Testing
if(TOBANTEAUDIO_ETL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Examples
if(TOBANTEAUDIO_ETL_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# Default Build Mode
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message("Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()