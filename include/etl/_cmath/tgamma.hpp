// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_TGAMMA_HPP
#define TETL_CMATH_TGAMMA_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto tgamma(float arg) noexcept -> float { return etl::detail::gcem::tgamma(arg); }

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto tgammaf(float arg) noexcept -> float { return etl::detail::gcem::tgamma(arg); }

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto tgamma(double arg) noexcept -> double { return etl::detail::gcem::tgamma(arg); }

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto tgamma(long double arg) noexcept -> long double { return etl::detail::gcem::tgamma(arg); }

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto tgammal(long double arg) noexcept -> long double { return etl::detail::gcem::tgamma(arg); }

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto tgamma(T arg) noexcept -> double
{
    return etl::detail::gcem::tgamma(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TGAMMA_HPP
