/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_COSH_HPP
#define TETL_CMATH_COSH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto cosh(float arg) noexcept -> float
{
    return etl::detail::gcem::cosh(arg);
}

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto coshf(float arg) noexcept -> float
{
    return etl::detail::gcem::cosh(arg);
}

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto cosh(double arg) noexcept -> double
{
    return etl::detail::gcem::cosh(arg);
}

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto cosh(long double arg) noexcept -> long double
{
    return etl::detail::gcem::cosh(arg);
}

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto coshl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::cosh(arg);
}

/// \brief Computes the hyperbolic cosine of arg
/// https://en.cppreference.com/w/cpp/numeric/math/cosh
template <typename T>
[[nodiscard]] constexpr auto cosh(T arg) noexcept
    -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::cosh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_COSH_HPP