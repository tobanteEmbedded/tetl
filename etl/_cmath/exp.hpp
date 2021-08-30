/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_EXP_HPP
#define TETL_CMATH_EXP_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto exp(float v) noexcept -> float
{
    return gcem::exp(v);
}

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto expf(float v) noexcept -> float
{
    return gcem::exp(v);
}

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto exp(double v) noexcept -> double
{
    return gcem::exp(v);
}

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto exp(long double v) noexcept -> long double
{
    return gcem::exp(v);
}

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto expl(long double v) noexcept -> long double
{
    return gcem::exp(v);
}

/// \brief Computes e (Euler's number, 2.7182...) raised to the given power v
/// https://en.cppreference.com/w/cpp/numeric/math/exp
template <typename T>
[[nodiscard]] constexpr auto exp(T v) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::exp(static_cast<double>(v));
}

} // namespace etl

#endif // TETL_CMATH_EXP_HPP