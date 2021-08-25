/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONFIG_COMPILER_HPP
#define TETL_CONFIG_COMPILER_HPP

#if defined(__clang__)
#define TETL_CLANG 1
#elif defined(__GNUC__)
#define TETL_GCC 1
#elif defined(_MSC_VER)
#define TETL_MSVC 1
#elif defined(__INTEL_COMPILER)
#define TETL_INTEL 1
#elif defined(__EMSCRIPTEN__)
#define TETL_EMSCRIPTEN 1
#else
#error "unknown compiler"
#endif

#endif // TETL_CONFIG_COMPILER_HPP