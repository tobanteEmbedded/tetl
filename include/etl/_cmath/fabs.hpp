// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FABS_HPP
#define TETL_CMATH_FABS_HPP

#include <etl/_math/abs.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fabs
[[nodiscard]] constexpr auto fabs(float arg) noexcept -> float
{
    return etl::detail::fabs(arg);
}

[[nodiscard]] constexpr auto fabsf(float arg) noexcept -> float
{
    return etl::detail::fabs(arg);
}

[[nodiscard]] constexpr auto fabs(double arg) noexcept -> double
{
    return etl::detail::fabs(arg);
}

[[nodiscard]] constexpr auto fabs(long double arg) noexcept -> long double
{
    return etl::detail::fabs(arg);
}

[[nodiscard]] constexpr auto fabsl(long double arg) noexcept -> long double
{
    return etl::detail::fabs(arg);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FABS_HPP
