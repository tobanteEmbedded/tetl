
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_CEIL_HPP
#define TETL_CMATH_CEIL_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Computes the smallest integer value not less than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceil(float arg) noexcept -> float { return etl::detail::gcem::ceil(arg); }
[[nodiscard]] constexpr auto ceilf(float arg) noexcept -> float { return etl::detail::gcem::ceil(arg); }
[[nodiscard]] constexpr auto ceil(double arg) noexcept -> double { return etl::detail::gcem::ceil(arg); }
[[nodiscard]] constexpr auto ceil(long double arg) noexcept -> long double { return etl::detail::gcem::ceil(arg); }
[[nodiscard]] constexpr auto ceill(long double arg) noexcept -> long double { return etl::detail::gcem::ceil(arg); }
[[nodiscard]] constexpr auto ceil(integral auto arg) noexcept -> double { return etl::detail::gcem::ceil(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_CEIL_HPP
