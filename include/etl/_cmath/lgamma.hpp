// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LGAMMA_HPP
#define TETL_CMATH_LGAMMA_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(float arg) noexcept -> float
{
    return etl::detail::gcem::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgammaf(float arg) noexcept -> float
{
    return etl::detail::gcem::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(double arg) noexcept -> double
{
    return etl::detail::gcem::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(long double arg) noexcept -> long double
{
    return etl::detail::gcem::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgammal(long double arg) noexcept -> long double
{
    return etl::detail::gcem::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto lgamma(T arg) noexcept -> double
{
    return etl::detail::gcem::lgamma(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LGAMMA_HPP
