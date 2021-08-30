/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_TAN_HPP
#define TETL_CMATH_TAN_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tan(float arg) noexcept -> float
{
    return etl::detail::gcem::tan(arg);
}

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tanf(float arg) noexcept -> float
{
    return etl::detail::gcem::tan(arg);
}

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tan(double arg) noexcept -> double
{
    return etl::detail::gcem::tan(arg);
}

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tan(long double arg) noexcept -> long double
{
    return etl::detail::gcem::tan(arg);
}

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tanl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::tan(arg);
}

/// \brief Computes the tangent of arg (measured in radians).
/// https://en.cppreference.com/w/cpp/numeric/math/tan
template <typename T>
[[nodiscard]] constexpr auto tan(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::tan(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TAN_HPP