/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FMIN_HPP
#define TETL_CMATH_FMIN_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fmin(float x, float y) noexcept -> float
{
    return etl::detail::gcem::min(x, y);
}

/// \brief Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fminf(float x, float y) noexcept -> float
{
    return etl::detail::gcem::min(x, y);
}

/// \brief Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fmin(double x, double y) noexcept -> double
{
    return etl::detail::gcem::min(x, y);
}

/// \brief Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fmin(long double x, long double y) noexcept
    -> long double
{
    return etl::detail::gcem::min(x, y);
}

/// \brief Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fminl(long double x, long double y) noexcept
    -> long double
{
    return etl::detail::gcem::min(x, y);
}

} // namespace etl

#endif // TETL_CMATH_FMIN_HPP