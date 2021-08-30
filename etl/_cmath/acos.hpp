/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ACOS_HPP
#define TETL_CMATH_ACOS_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acos(float arg) noexcept -> float
{
    return etl::detail::gcem::acos(arg);
}

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acosf(float arg) noexcept -> float
{
    return etl::detail::gcem::acos(arg);
}

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acos(double arg) noexcept -> double
{
    return etl::detail::gcem::acos(arg);
}

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acos(long double arg) noexcept -> long double
{
    return etl::detail::gcem::acos(arg);
}

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acosl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::acos(arg);
}

/// \brief Computes the principal value of the arc cosine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/acos
template <typename T>
[[nodiscard]] constexpr auto acos(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::acos(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ACOS_HPP