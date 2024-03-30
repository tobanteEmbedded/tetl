// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_SQRT_HPP
#define TETL_CMATH_SQRT_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
[[nodiscard]] constexpr auto sqrt(float arg) noexcept -> float { return etl::detail::gcem::sqrt(arg); }

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
[[nodiscard]] constexpr auto sqrtf(float arg) noexcept -> float { return etl::detail::gcem::sqrt(arg); }

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
[[nodiscard]] constexpr auto sqrt(double arg) noexcept -> double { return etl::detail::gcem::sqrt(arg); }

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
[[nodiscard]] constexpr auto sqrt(long double arg) noexcept -> long double { return etl::detail::gcem::sqrt(arg); }

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
[[nodiscard]] constexpr auto sqrtl(long double arg) noexcept -> long double { return etl::detail::gcem::sqrt(arg); }

/// \brief Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto sqrt(T arg) noexcept -> double
{
    return etl::detail::gcem::sqrt(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_SQRT_HPP
