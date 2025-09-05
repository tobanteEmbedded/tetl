// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_COSH_HPP
#define TETL_CMATH_COSH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Computes the hyperbolic cosine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto cosh(float arg) noexcept -> float
{
    return etl::detail::gcem::cosh(arg);
}
[[nodiscard]] constexpr auto coshf(float arg) noexcept -> float
{
    return etl::detail::gcem::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(double arg) noexcept -> double
{
    return etl::detail::gcem::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(long double arg) noexcept -> long double
{
    return etl::detail::gcem::cosh(arg);
}
[[nodiscard]] constexpr auto coshl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(integral auto arg) noexcept -> double
{
    return etl::detail::gcem::cosh(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_COSH_HPP
