/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_SQRT_HPP
#define TETL_CMATH_SQRT_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(float arg) noexcept -> float
{
    return gcem::sqrt(arg);
}

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrtf(float arg) noexcept -> float
{
    return gcem::sqrt(arg);
}

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(double arg) noexcept -> double
{
    return gcem::sqrt(arg);
}

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(long double arg) noexcept -> long double
{
    return gcem::sqrt(arg);
}

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrtl(long double arg) noexcept -> long double
{
    return gcem::sqrt(arg);
}

/// \brief Computes the square root of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/sqrt
template <typename T>
[[nodiscard]] constexpr auto sqrt(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::sqrt(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_SQRT_HPP