/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ERF_HPP
#define TETL_CMATH_ERF_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(float arg) noexcept -> float
{
    return etl::detail::gcem::erf(arg);
}

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erff(float arg) noexcept -> float
{
    return etl::detail::gcem::erf(arg);
}

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(double arg) noexcept -> double
{
    return etl::detail::gcem::erf(arg);
}

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(long double arg) noexcept -> long double
{
    return etl::detail::gcem::erf(arg);
}

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erfl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::erf(arg);
}

/// \brief Computes the error function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/erf
template <typename T>
[[nodiscard]] constexpr auto erf(T arg) noexcept
    -> etl::enable_if<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::erf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ERF_HPP