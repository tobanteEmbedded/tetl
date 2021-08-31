/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ASIN_HPP
#define TETL_CMATH_ASIN_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(float arg) noexcept -> float
{
    return etl::detail::gcem::asin(arg);
}

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asinf(float arg) noexcept -> float
{
    return etl::detail::gcem::asin(arg);
}

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(double arg) noexcept -> double
{
    return etl::detail::gcem::asin(arg);
}

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(long double arg) noexcept -> long double
{
    return etl::detail::gcem::asin(arg);
}

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asinl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::asin(arg);
}

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
template <typename T>
[[nodiscard]] constexpr auto asin(T arg) noexcept
    -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::asin(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ASIN_HPP