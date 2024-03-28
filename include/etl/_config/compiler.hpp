// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_COMPILER_HPP
#define TETL_CONFIG_COMPILER_HPP

#if defined(__clang__)
    #define TETL_COMPILER_CLANG
#elif defined(__GNUC__)
    #define TETL_COMPILER_GCC
#elif defined(_MSC_VER)
    #define TETL_COMPILER_MSVC
#else
    #define TETL_COMPILER_UNKOWN
#endif

#endif // TETL_CONFIG_COMPILER_HPP
