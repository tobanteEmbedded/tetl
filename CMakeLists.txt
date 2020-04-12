cmake_minimum_required(VERSION 3.8)

# Project
project(TobanteAudioEmbeddedTemplateLibrary LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

# Options
option(TOBANTEAUDIO_ETL_BUILD_EXAMPLES  "Build examples" ON)
option(TOBANTEAUDIO_ETL_BUILD_TESTS     "Build unit tests" ON)
option(TOBANTEAUDIO_ETL_BUILD_DOCS      "Build documentation" ON)
option(TOBANTEAUDIO_ETL_ENABLE_COVERAGE "Enable coverage reporting for gcc/clang" FALSE)

# Cmake setup
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)
include(CodeCoverage)
include(BuildDoxygen)

# Main Project
add_subdirectory(src)

# Documentation (doxygen)
if(TOBANTEAUDIO_ETL_BUILD_DOCS)
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

# Default Build Mode
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message("Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()