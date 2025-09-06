# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

add_library(tetl.compiler_warnings INTERFACE)
add_library(tetl::compiler_warnings ALIAS tetl.compiler_warnings)

if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "/W3"
        "/wd4723" # potential divide by 0
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "-Wall"
        "-Wextra"
        "-Wpedantic"

        "-Wcast-qual"
        "-Wdisabled-optimization"
        "-Wdouble-promotion"
        "-Wduplicated-branches"
        "-Wduplicated-cond"
        "-Wformat=2"
        "-Winit-self"
        "-Winvalid-pch"
        "-Wlogical-op"
        "-Wmisleading-indentation"
        "-Wmissing-declarations"
        "-Wmissing-field-initializers"
        "-Wmissing-include-dirs"
        "-Wnarrowing"
        "-Wold-style-cast"
        "-Woverloaded-virtual"
        "-Wredundant-decls"
        "-Wreorder"
        "-Wshadow"
        "-Wsign-compare"
        "-Wsign-conversion"
        "-Wsign-promo"
        "-Wstrict-aliasing"
        "-Wstrict-null-sentinel"
        "-Wstrict-overflow=1"
        "-Wswitch-enum"
        "-Wtrampolines"
        "-Wundef"
        "-Wuninitialized"
        "-Wunreachable-code"
        "-Wunused-parameter"
        "-Wvector-operation-performance"
        "-Wzero-as-null-pointer-constant"

        "-Wno-cast-align" # warns on arm-gcc-none-eabi, but not on avr or x86
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "-Weverything"

        "-Wno-c++98-compat-pedantic"
        "-Wno-c++20-compat"
        "-Wno-ctad-maybe-unsupported"
        "-Wno-float-equal"
        "-Wno-padded"
        "-Wno-unsafe-buffer-usage"
        "-Wno-unused-member-function"
        "-Wno-weak-vtables"
    )
endif ()
