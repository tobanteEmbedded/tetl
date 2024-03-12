// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ASIN_HPP
#define TETL_CMATH_ASIN_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(float arg) noexcept -> float { return etl::detail::gcem::asin(arg); }

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asinf(float arg) noexcept -> float { return etl::detail::gcem::asin(arg); }

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(double arg) noexcept -> double { return etl::detail::gcem::asin(arg); }

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(long double arg) noexcept -> long double { return etl::detail::gcem::asin(arg); }

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asinl(long double arg) noexcept -> long double { return etl::detail::gcem::asin(arg); }

/// \brief Computes the principal value of the arc sine of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/asin
template <integral T>
[[nodiscard]] constexpr auto asin(T arg) noexcept -> double
{
    return etl::detail::gcem::asin(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ASIN_HPP
