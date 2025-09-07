// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_BETA_HPP
#define TETL_CMATH_BETA_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Computes the beta function of x and y.
/// \details https://en.cppreference.com/w/cpp/numeric/special_functions/beta
[[nodiscard]] constexpr auto beta(double x, double y) noexcept -> double
{
    return etl::detail::gcem::beta(x, y);
}
[[nodiscard]] constexpr auto betaf(float x, float y) noexcept -> float
{
    return etl::detail::gcem::beta(x, y);
}
[[nodiscard]] constexpr auto betal(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::beta(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_BETA_HPP
