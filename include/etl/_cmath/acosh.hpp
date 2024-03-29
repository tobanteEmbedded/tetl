// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ACOSH_HPP
#define TETL_CMATH_ACOSH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
[[nodiscard]] constexpr auto acosh(float arg) noexcept -> float { return etl::detail::gcem::acosh(arg); }

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
[[nodiscard]] constexpr auto acoshf(float arg) noexcept -> float { return etl::detail::gcem::acosh(arg); }

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
[[nodiscard]] constexpr auto acosh(double arg) noexcept -> double { return etl::detail::gcem::acosh(arg); }

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
[[nodiscard]] constexpr auto acosh(long double arg) noexcept -> long double { return etl::detail::gcem::acosh(arg); }

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
[[nodiscard]] constexpr auto acoshl(long double arg) noexcept -> long double { return etl::detail::gcem::acosh(arg); }

/// \brief Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto acosh(T arg) noexcept -> double
{
    return etl::detail::gcem::acosh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ACOSH_HPP
