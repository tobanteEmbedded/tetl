/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_TRUNC_HPP
#define TETL_CMATH_TRUNC_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(float arg) noexcept -> float
{
    return gcem::trunc(arg);
}

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto truncf(float arg) noexcept -> float
{
    return gcem::trunc(arg);
}

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(double arg) noexcept -> double
{
    return gcem::trunc(arg);
}

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(long double arg) noexcept -> long double
{
    return gcem::trunc(arg);
}

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto truncl(long double arg) noexcept -> long double
{
    return gcem::trunc(arg);
}

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
template <typename T>
[[nodiscard]] constexpr auto trunc(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::trunc(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TRUNC_HPP