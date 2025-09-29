# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

include_guard(GLOBAL)

set(ATFE_TOOLCHAIN "" CACHE STRING "Path to ARM toolchain for Embedded")

if(NOT DEFINED ATFE_TOOLCHAIN)
    message(FATAL_ERROR "Could not find ATfE. Use CMake variable ATFE_TOOLCHAIN")
else()
    if(NOT EXISTS "${ATFE_TOOLCHAIN}/bin/clang")
        message(FATAL_ERROR "ATFE_TOOLCHAIN does not point to a valid ATfE installation")
    endif()
endif()

set(CMAKE_SYSTEM_NAME       Generic-ELF)
set(CMAKE_SYSTEM_PROCESSOR  arm)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_C_COMPILER "${ATFE_TOOLCHAIN}/bin/clang")
set(CMAKE_CXX_COMPILER "${ATFE_TOOLCHAIN}/bin/clang++")

set(ARCH_FLAGS "--target=armv6m-none-eabi -march=armv6m -mfpu=none -mfloat-abi=soft -flto")
set(CPP_FLAGS "-fno-exceptions -fno-rtti")

set(CMAKE_C_FLAGS_DEBUG "${ARCH_FLAGS} -O0 -g3")
set(CMAKE_CXX_FLAGS_DEBUG "${ARCH_FLAGS} ${CPP_FLAGS} -O0 -g3")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "${ARCH_FLAGS} -O3 -g3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${ARCH_FLAGS} ${CPP_FLAGS} -O3 -g3 -DNDEBUG")

set(CMAKE_C_FLAGS_RELEASE "${ARCH_FLAGS} -O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${ARCH_FLAGS} ${CPP_FLAGS} -O3 -DNDEBUG")

set(CMAKE_C_FLAGS_MINSIZEREL "${ARCH_FLAGS} -Oz -g3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${ARCH_FLAGS} ${CPP_FLAGS} -Oz -g3 -DNDEBUG")

add_link_options(
    -nostartfiles
    -lcrt0-semihost
    -lsemihost
    -Wl,--gc-sections
    -Wl,-T "${ATFE_TOOLCHAIN}/samples/ldscripts/microbit.ld"
)
