
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_CEIL_HPP
#define TETL_CMATH_CEIL_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the smallest integer value not less than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceil(float arg) noexcept -> float
{
    return gcem::ceil(arg);
}

/// \brief Computes the smallest integer value not less than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceilf(float arg) noexcept -> float
{
    return gcem::ceil(arg);
}

/// \brief Computes the smallest integer value not less than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceil(double arg) noexcept -> double
{
    return gcem::ceil(arg);
}

/// \brief Computes the smallest integer value not less than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceil(long double arg) noexcept -> long double
{
    return gcem::ceil(arg);
}

/// \brief Computes the smallest integer value not less than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceill(long double arg) noexcept -> long double
{
    return gcem::ceil(arg);
}

} // namespace etl

#endif // TETL_CMATH_CEIL_HPP