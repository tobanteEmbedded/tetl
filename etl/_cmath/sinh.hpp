/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_SINH_HPP
#define TETL_CMATH_SINH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
[[nodiscard]] constexpr auto sinh(float arg) noexcept -> float
{
    return gcem::sinh(arg);
}

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
[[nodiscard]] constexpr auto sinhf(float arg) noexcept -> float
{
    return gcem::sinh(arg);
}

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
[[nodiscard]] constexpr auto sinh(double arg) noexcept -> double
{
    return gcem::sinh(arg);
}

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
[[nodiscard]] constexpr auto sinh(long double arg) noexcept -> long double
{
    return gcem::sinh(arg);
}

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
[[nodiscard]] constexpr auto sinhl(long double arg) noexcept -> long double
{
    return gcem::sinh(arg);
}

/// \brief Computes the hyperbolic sine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/sinh
template <typename T>
[[nodiscard]] constexpr auto sinh(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::sinh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_SINH_HPP