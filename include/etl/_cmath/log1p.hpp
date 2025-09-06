// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_LOG1P_HPP
#define TETL_CMATH_LOG1P_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1p(float v) noexcept -> float
{
    return etl::detail::gcem::log1p(v);
}
[[nodiscard]] constexpr auto log1pf(float v) noexcept -> float
{
    return etl::detail::gcem::log1p(v);
}
[[nodiscard]] constexpr auto log1p(double v) noexcept -> double
{
    return etl::detail::gcem::log1p(v);
}
[[nodiscard]] constexpr auto log1p(long double v) noexcept -> long double
{
    return etl::detail::gcem::log1p(v);
}
[[nodiscard]] constexpr auto log1pl(long double v) noexcept -> long double
{
    return etl::detail::gcem::log1p(v);
}
[[nodiscard]] constexpr auto log1p(integral auto arg) noexcept -> double
{
    return etl::detail::gcem::log1p(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_LOG1P_HPP
