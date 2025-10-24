# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

include_guard(GLOBAL)

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_ASM_COMPILER "riscv-none-elf-gcc")
set(CMAKE_C_COMPILER   "riscv-none-elf-gcc")
set(CMAKE_CXX_COMPILER "riscv-none-elf-g++")

set(CMAKE_AR           "riscv-none-elf-ar")
set(CMAKE_RANLIB       "riscv-none-elf-ranlib")
set(CMAKE_OBJCOPY      "riscv-none-elf-objcopy")
set(CMAKE_OBJDUMP      "riscv-none-elf-objdump")
set(CMAKE_SIZE         "riscv-none-elf-size")

set(RISCV_ARCH "rv32imc" CACHE STRING "RISC-V ISA string (e.g. rv32imc, rv32imac)")
set(RISCV_ABI  "ilp32"   CACHE STRING "RISC-V ABI (e.g. ilp32, ilp32e, ilp32f)")
set(RISCV_TUNE ""        CACHE STRING "Optional -mtune target for GCC (may be empty)")

set(RISCV_COMMON_FLAGS "-march=${RISCV_ARCH} -mabi=${RISCV_ABI} -mcmodel=medlow -ffunction-sections -fdata-sections -msave-restore")
if(NOT RISCV_TUNE STREQUAL "")
  set(RISCV_COMMON_FLAGS "${RISCV_COMMON_FLAGS} -mtune=${RISCV_TUNE}")
endif()

set(CMAKE_C_FLAGS_INIT   "${RISCV_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${RISCV_COMMON_FLAGS}")

set(RISCV_LD_COMMON "-Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS_INIT     "${RISCV_LD_COMMON}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT  "${RISCV_LD_COMMON}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT  "${RISCV_LD_COMMON}")
