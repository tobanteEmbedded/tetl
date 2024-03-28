// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_TYPEDEFS_HPP
#define TETL_CMATH_TYPEDEFS_HPP

#include <etl/_config/all.hpp>

#if defined(TETL_COMPILER_MSVC)
    #include <math.h>
#else
    #ifndef NAN
        #define NAN TETL_BUILTIN_NAN("")
    #endif

    #ifndef INFINITY
        #define INFINITY TETL_BUILTIN_HUGE_VALF
    #endif

    #ifndef HUGE_VALF
        #define HUGE_VALF TETL_BUILTIN_HUGE_VALF
    #endif

    #ifndef HUGE_VAL
        #define HUGE_VAL TETL_BUILTIN_HUGE_VAL
    #endif

    #ifndef HUGE_VALL
        #define HUGE_VALL TETL_BUILTIN_HUGE_VALL
    #endif
#endif

namespace etl {
/// \brief Most efficient floating-point type at least as wide as float.
using float_t = float;

/// \brief Most efficient floating-point type at least as wide as double.
using double_t = double;
} // namespace etl

#endif // TETL_CMATH_TYPEDEFS_HPP
