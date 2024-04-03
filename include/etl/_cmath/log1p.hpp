// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LOG1P_HPP
#define TETL_CMATH_LOG1P_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
[[nodiscard]] constexpr auto log1p(float v) noexcept -> float { return etl::detail::gcem::log1p(v); }

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
[[nodiscard]] constexpr auto log1pf(float v) noexcept -> float { return etl::detail::gcem::log1p(v); }

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
[[nodiscard]] constexpr auto log1p(double v) noexcept -> double { return etl::detail::gcem::log1p(v); }

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
[[nodiscard]] constexpr auto log1p(long double v) noexcept -> long double { return etl::detail::gcem::log1p(v); }

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
[[nodiscard]] constexpr auto log1pl(long double v) noexcept -> long double { return etl::detail::gcem::log1p(v); }

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto log1p(T arg) noexcept -> double
{
    return etl::detail::gcem::log1p(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG1P_HPP
