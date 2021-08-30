/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_CMATH_HPP
#define TETL_CMATH_CMATH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cos(float arg) noexcept -> float
{
    return gcem::cos(arg);
}

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cosf(float arg) noexcept -> float
{
    return gcem::cos(arg);
}

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cos(double arg) noexcept -> double
{
    return gcem::cos(arg);
}

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cos(long double arg) noexcept -> long double
{
    return gcem::cos(arg);
}

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cosl(long double arg) noexcept -> long double
{
    return gcem::cos(arg);
}

/// \brief Computes the cosine of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/cos
template <typename T>
[[nodiscard]] constexpr auto cos(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::cos(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_CMATH_HPP