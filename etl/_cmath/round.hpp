/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ROUND_HPP
#define TETL_CMATH_ROUND_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(float arg) noexcept -> float
{
    return gcem::round(arg);
}

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto roundf(float arg) noexcept -> float
{
    return gcem::round(arg);
}

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(double arg) noexcept -> double
{
    return gcem::round(arg);
}

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(long double arg) noexcept -> long double
{
    return gcem::round(arg);
}

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto roundl(long double arg) noexcept -> long double
{
    return gcem::round(arg);
}

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
template <typename T>
[[nodiscard]] constexpr auto round(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::round(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ROUND_HPP