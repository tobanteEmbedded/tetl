/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_COPYSIGN_HPP
#define TETL_CMATH_COPYSIGN_HPP

#include "etl/_config/all.hpp"

namespace etl {

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
    return TETL_BUILTIN_COPYSIGNF(mag, sgn);
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
    return TETL_BUILTIN_COPYSIGNF(mag, sgn);
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
    return TETL_BUILTIN_COPYSIGNL(mag, sgn);
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
    return TETL_BUILTIN_COPYSIGNL(mag, sgn);
}

} // namespace etl

#endif // TETL_CMATH_COPYSIGN_HPP