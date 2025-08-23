include_guard(GLOBAL)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}")
include(stm32)

set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_SYSTEM_NAME Generic-ELF)

set(CMAKE_C_COMPILER    "arm-none-eabi-gcc")
set(CMAKE_CXX_COMPILER  "arm-none-eabi-g++")

set(CMAKE_LINKER        "arm-none-eabi-gcc")
set(CMAKE_AR            "arm-none-eabi-gcc-ar")
set(CMAKE_RANLIB        "arm-none-eabi-gcc-ranlib")
set(CMAKE_OBJCOPY       "arm-none-eabi-objcopy")

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
    --specs=nano.specs
    --specs=nosys.specs
    # -Wl,-T /home/tobante/Developer/tobanteEmbedded/tetl/link.lds
)

set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")

set(CMAKE_C_FLAGS_DEBUG            "-Og -g3 -gdwarf-4 -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG          "-Og -g3 -gdwarf-4 -DDEBUG")
set(CMAKE_ASM_FLAGS_DEBUG          "-g3 -gdwarf-4 -DDEBUG")

set(CMAKE_C_FLAGS_RELWITHDEBINFO   "-Os -g3 -gdwarf-4 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-Os -g3 -gdwarf-4 -DNDEBUG")
set(CMAKE_ASM_FLAGS_RELWITHDEBINFO "-g3 -gdwarf-4 -DNDEBUG")

set(CMAKE_C_FLAGS_RELEASE          "-Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-Os -DNDEBUG")
set(CMAKE_ASM_FLAGS_RELEASE        "-DNDEBUG")
