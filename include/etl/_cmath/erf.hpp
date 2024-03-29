// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ERF_HPP
#define TETL_CMATH_ERF_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(float arg) noexcept -> float { return etl::detail::gcem::erf(arg); }

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erff(float arg) noexcept -> float { return etl::detail::gcem::erf(arg); }

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(double arg) noexcept -> double { return etl::detail::gcem::erf(arg); }

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(long double arg) noexcept -> long double { return etl::detail::gcem::erf(arg); }

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erfl(long double arg) noexcept -> long double { return etl::detail::gcem::erf(arg); }

/// \brief Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
template <integral T>
[[nodiscard]] constexpr auto erf(T arg) noexcept -> double
{
    return etl::detail::gcem::erf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ERF_HPP
