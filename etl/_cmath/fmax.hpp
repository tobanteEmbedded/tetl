/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FMAX_HPP
#define TETL_CMATH_FMAX_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmax(float x, float y) noexcept -> float
{
    return gcem::max(x, y);
}

/// \brief Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmaxf(float x, float y) noexcept -> float
{
    return gcem::max(x, y);
}

/// \brief Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmax(double x, double y) noexcept -> double
{
    return gcem::max(x, y);
}

/// \brief Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmax(long double x, long double y) noexcept
    -> long double
{
    return gcem::max(x, y);
}

/// \brief Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmaxl(long double x, long double y) noexcept
    -> long double
{
    return gcem::max(x, y);
}

} // namespace etl

#endif // TETL_CMATH_FMAX_HPP