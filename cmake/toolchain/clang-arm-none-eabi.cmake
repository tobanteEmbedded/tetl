include_guard(GLOBAL)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}")
include(stm32)

execute_process(
    COMMAND arm-none-eabi-gcc ${MCU} -print-sysroot
    OUTPUT_VARIABLE GCC_SYSROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND arm-none-eabi-gcc ${MCU} -print-multi-directory
    OUTPUT_VARIABLE GCC_MULTIDIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND arm-none-eabi-gcc ${MCU} -print-libgcc-file-name
    OUTPUT_VARIABLE GCC_BUILTINS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_SYSTEM_NAME Generic-ELF)
set(CMAKE_SYSROOT ${GCC_SYSROOT})

set(CMAKE_C_COMPILER_TARGET arm-none-eabi)
set(CMAKE_CXX_COMPILER_TARGET arm-none-eabi)
set(CMAKE_ASM_COMPILER_TARGET arm-none-eabi)

set(CMAKE_C_COMPILER    "clang")
set(CMAKE_CXX_COMPILER  "clang++")

set(CMAKE_AR            "llvm-ar")
set(CMAKE_LINKER        "lld")
set(CMAKE_NM            "llvm-nm")
set(CMAKE_OBJCOPY       "llvm-objcopy")
set(CMAKE_RANLIB        "llvm-ranlib")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(COMMON_FLAGS
    -nostdlib
    $<$<COMPILE_LANGUAGE:CXX>:-nostdlib++>
    $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>

    -fno-exceptions
    -ffunction-sections
    -fdata-sections
    -fomit-frame-pointer
    -finline-functions
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

add_compile_options(${COMMON_FLAGS})
add_link_options(
    ${COMMON_FLAGS}
    -Wl,--gc-sections
    -L ${CMAKE_SYSROOT}/lib/${GCC_MULTIDIR} ${GCC_BUILTINS}
)

set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")

set(CMAKE_C_FLAGS_DEBUG            "-Og -g3 -gdwarf-4 -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG          "-Og -g3 -gdwarf-4 -DDEBUG")
set(CMAKE_ASM_FLAGS_DEBUG          "-g3 -gdwarf-4 -DDEBUG")

set(CMAKE_C_FLAGS_RELEASE          "-Oz -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-Oz -DNDEBUG")
set(CMAKE_ASM_FLAGS_RELEASE        "-DNDEBUG")

set(CMAKE_C_FLAGS_RELWITHDEBINFO   "-Oz -g3 -gdwarf-4 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-Oz -g3 -gdwarf-4 -DNDEBUG")
set(CMAKE_ASM_FLAGS_RELWITHDEBINFO "-g3 -gdwarf-4 -DNDEBUG")
