/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_LGAMMA_HPP
#define TETL_CMATH_LGAMMA_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
[[nodiscard]] constexpr auto lgamma(float arg) noexcept -> float
{
    return etl::detail::gcem::lgamma(arg);
}

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
[[nodiscard]] constexpr auto lgammaf(float arg) noexcept -> float
{
    return etl::detail::gcem::lgamma(arg);
}

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
[[nodiscard]] constexpr auto lgamma(double arg) noexcept -> double
{
    return etl::detail::gcem::lgamma(arg);
}

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
[[nodiscard]] constexpr auto lgamma(long double arg) noexcept -> long double
{
    return etl::detail::gcem::lgamma(arg);
}

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
[[nodiscard]] constexpr auto lgammal(long double arg) noexcept -> long double
{
    return etl::detail::gcem::lgamma(arg);
}

/// \brief Computes the natural logarithm of the absolute value of the gamma
/// function of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/lgamma
template <typename T>
[[nodiscard]] constexpr auto lgamma(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::lgamma(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LGAMMA_HPP