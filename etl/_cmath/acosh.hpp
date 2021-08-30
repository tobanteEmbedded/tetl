/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ACOSH_HPP
#define TETL_CMATH_ACOSH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acosh(float arg) noexcept -> float
{
    return gcem::acosh(arg);
}

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acoshf(float arg) noexcept -> float
{
    return gcem::acosh(arg);
}

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acosh(double arg) noexcept -> double
{
    return gcem::acosh(arg);
}

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acosh(long double arg) noexcept -> long double
{
    return gcem::acosh(arg);
}

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acoshl(long double arg) noexcept -> long double
{
    return gcem::acosh(arg);
}

/// \brief Computes the inverse hyperbolic cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acosh
template <typename T>
[[nodiscard]] constexpr auto acosh(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return gcem::acosh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ACOSH_HPP