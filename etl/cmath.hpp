// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CMATH_HPP
#define TETL_CMATH_HPP

#include "etl/version.hpp"

#include "etl/type_traits.hpp"

#include "etl/detail/math/abs.hpp"
#include "etl/detail/math/lerp.hpp"

#include "etl/detail/type_traits/enable_if.hpp"

#if __has_include(<math.h>)
#include <math.h>
#else

#ifndef NAN
#define NAN TETL_BUILTIN_NAN("")
#endif

#ifndef INFINITY
#define INFINITY TETL_BUILTIN_HUGE_VAL
#endif

#endif // has_include<math.h>

namespace etl {
/// \brief Most efficient floating-point type at least as wide as float.
using float_t = float;

/// \brief Most efficient floating-point type at least as wide as double.
using double_t = double;

/// \brief Determines if the given floating point number arg is a positive or
/// negative infinity.
/// \returns true if arg is infinite, false otherwise
/// \notes
/// [cppreference.com/w/cpp/numeric/math/isinf](https://en.cppreference.com/w/cpp/numeric/math/isinf)
/// \group isinf
/// \module Numeric
[[nodiscard]] constexpr auto isinf(float arg) -> bool
{
    return arg == INFINITY;
}

/// \group isinf
[[nodiscard]] constexpr auto isinf(double arg) -> bool
{
    return arg == INFINITY;
}

/// \group isinf
[[nodiscard]] constexpr auto isinf(long double arg) -> bool
{
    return arg == INFINITY;
}

/// \group isinf
template <typename Int>
[[nodiscard]] constexpr auto isinf(Int arg)
    -> enable_if_t<is_integral_v<Int>, bool>
{
    return isinf(static_cast<double>(arg));
}

/// \brief Determines if the given floating point number arg is a not-a-number
/// (NaN) value.
/// \notes
/// [cppreference.com/w/cpp/numeric/math/isnan](https://en.cppreference.com/w/cpp/numeric/math/isnan)
/// \group isnan
/// \module Numeric
[[nodiscard]] constexpr auto isnan(float arg) -> bool { return arg != arg; }

/// \group isnan
[[nodiscard]] constexpr auto isnan(double arg) -> bool { return arg != arg; }

/// \group isnan
[[nodiscard]] constexpr auto isnan(long double arg) -> bool
{
    return arg != arg;
}

/// \brief Determines if the given floating point number arg is a not-a-number
/// (NaN) value.
/// \notes
/// [cppreference.com/w/cpp/numeric/math/isnan](https://en.cppreference.com/w/cpp/numeric/math/isnan)
template <typename Int>
[[nodiscard]] constexpr auto isnan(Int arg)
    -> enable_if_t<is_integral_v<Int>, bool>
{
    return isnan(static_cast<double>(arg));
}

/// \brief Determines if the given floating point number arg has finite value
/// i.e. it is normal, subnormal or zero, but not infinite or NaN.
/// \notes
/// [cppreference.com/w/cpp/numeric/math/isfinite](https://en.cppreference.com/w/cpp/numeric/math/isfinite)
/// \group isfinite
/// \module Numeric
[[nodiscard]] constexpr auto isfinite(float arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/// \group isfinite
[[nodiscard]] constexpr auto isfinite(double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/// \group isfinite
[[nodiscard]] constexpr auto isfinite(long double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/// \brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
/// the parameter t (or extrapolation, when t is outside the range [0,1]).
/// \notes
/// [cppreference.com/w/cpp/numeric/lerp](https://en.cppreference.com/w/cpp/numeric/lerp)
/// \group lerp
/// \module Numeric
[[nodiscard]] constexpr auto lerp(float a, float b, float t) noexcept -> float
{
    return detail::lerp_impl<float>(a, b, t);
}

/// \group lerp
[[nodiscard]] constexpr auto lerp(double a, double b, double t) noexcept
    -> double
{
    return detail::lerp_impl<double>(a, b, t);
}

/// \group lerp
[[nodiscard]] constexpr auto lerp(
    long double a, long double b, long double t) noexcept -> long double
{
    return detail::lerp_impl<long double>(a, b, t);
}

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
/// \group abs
/// \module Numeric
[[nodiscard]] constexpr auto abs(int n) noexcept -> int
{
    return detail::abs_impl<int>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long n) noexcept -> long
{
    return detail::abs_impl<long>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long long n) noexcept -> long long
{
    return detail::abs_impl<long long>(n);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(float mag, float sgn) -> float
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignf(float mag, float sgn) -> float
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(double mag, double sgn) -> double
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(long double mag, long double sgn)
    -> long double
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignl(long double mag, long double sgn)
    -> long double
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(float arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(double arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(long double arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

} // namespace etl

#endif // TETL_CMATH_HPP
