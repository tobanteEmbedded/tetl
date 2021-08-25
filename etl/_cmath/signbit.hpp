/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_SIGNBIT_HPP
#define TETL_CMATH_SIGNBIT_HPP

#include "etl/_config/builtin_functions.hpp"

namespace etl {

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

#endif // TETL_CMATH_SIGNBIT_HPP