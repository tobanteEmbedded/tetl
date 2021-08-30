/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_TANH_HPP
#define TETL_CMATH_TANH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanh(float arg) noexcept -> float
{
    return gcem::tanh(arg);
}

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanhf(float arg) noexcept -> float
{
    return gcem::tanh(arg);
}

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanh(double arg) noexcept -> double
{
    return gcem::tanh(arg);
}

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanh(long double arg) noexcept -> long double
{
    return gcem::tanh(arg);
}

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanhl(long double arg) noexcept -> long double
{
    return gcem::tanh(arg);
}

/// \brief Computes the hyperbolic tangent of arg
/// https://en.cppreference.com/w/cpp/numeric/math/tanh
template <typename T>
[[nodiscard]] constexpr auto tanh(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::tanh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TANH_HPP