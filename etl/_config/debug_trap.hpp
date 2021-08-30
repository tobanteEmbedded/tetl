/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONFIG_DEBUG_TRAP_HPP
#define TETL_CONFIG_DEBUG_TRAP_HPP

#include "etl/_config/attributes.hpp"
#include "etl/_config/preprocessor.hpp"

#if !defined(TETL_NDEBUG) && defined(NDEBUG) && !defined(TETL_DEBUG)
    #define TETL_NDEBUG 1
#else
    #define TETL_DEBUG 1
#endif

#if defined(_MSC_VER)
    #define TETL_DEBUG_TRAP __debugbreak
#else

    #define TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION 1
    #define TETL_DEBUG_TRAP_IMPL_BULTIN_TRAP 2
    #define TETL_DEBUG_TRAP_IMPL_SIGTRAP 3

    #if defined(__i386__) || defined(__x86_64__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile("int $0x03"); }
    #elif defined(__thumb__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile(".inst 0xde01"); }
    #elif defined(__arm__) && !defined(__thumb__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile(".inst 0xe7f001f0"); }
    #elif defined(__aarch64__) && defined(__APPLE__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_BULTIN_DEBUGTRAP
    #elif defined(__aarch64__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile(".inst 0xd4200000"); }
    #elif defined(__powerpc__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile(".4byte 0x7d821008"); }
    #elif defined(__riscv)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { __asm__ volatile(".4byte 0x00100073"); }
    #elif defined(__AVR__)
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { }
    #elif defined(__STDC_HOSTED__) // hosted builds
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_SIGTRAP
    #else
        // TETL_DEBUG_TRAP is not supported on this target
        #define TETL_DEBUG_TRAP_IMPL TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto trap_inst() -> void { }
    #endif

    #if !defined(TETL_DEBUG_TRAP_IMPL)
inline auto TETL_DEBUG_TRAP() -> void { }
    #elif TETL_DEBUG_TRAP_IMPL == TETL_DEBUG_TRAP_IMPL_TRAP_INSTRUCTION
inline auto TETL_DEBUG_TRAP() -> void { trap_inst(); }
    #elif TETL_DEBUG_TRAP_IMPL == TETL_DEBUG_TRAP_IMPL_BULTIN_DEBUGTRAP
inline auto TETL_DEBUG_TRAP() -> void { __builtin_debugtrap(); }
    #elif TETL_DEBUG_TRAP_IMPL == TETL_DEBUG_TRAP_IMPL_BULTIN_TRAP
inline auto TETL_DEBUG_TRAP() -> void { __builtin_trap(); }
    #elif TETL_DEBUG_TRAP_IMPL == TETL_DEBUG_TRAP_IMPL_SIGTRAP
        #include <signal.h>
inline auto TETL_DEBUG_TRAP() -> void { ::raise(SIGTRAP); }
    #else
        #error "invalid TETL_DEBUG_TRAP_IMPL value"
    #endif

#endif

#endif // TETL_CONFIG_DEBUG_TRAP_HPP