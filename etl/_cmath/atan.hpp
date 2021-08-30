/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ATAN_HPP
#define TETL_CMATH_ATAN_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atan(float arg) noexcept -> float
{
    return etl::detail::gcem::atan(arg);
}

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atanf(float arg) noexcept -> float
{
    return etl::detail::gcem::atan(arg);
}

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atan(double arg) noexcept -> double
{
    return etl::detail::gcem::atan(arg);
}

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atan(long double arg) noexcept -> long double
{
    return etl::detail::gcem::atan(arg);
}

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atanl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::atan(arg);
}

/// \brief Computes the principal value of the arc tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atan
template <typename T>
[[nodiscard]] constexpr auto atan(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::atan(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ATAN_HPP