// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ATANH_HPP
#define TETL_CMATH_ATANH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Computes the inverse hyperbolic tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanh(float arg) noexcept -> float
{
    return etl::detail::gcem::atanh(arg);
}
[[nodiscard]] constexpr auto atanhf(float arg) noexcept -> float
{
    return etl::detail::gcem::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(double arg) noexcept -> double
{
    return etl::detail::gcem::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(long double arg) noexcept -> long double
{
    return etl::detail::gcem::atanh(arg);
}
[[nodiscard]] constexpr auto atanhl(long double arg) noexcept -> long double
{
    return etl::detail::gcem::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(integral auto arg) noexcept -> double
{
    return etl::detail::gcem::atanh(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ATANH_HPP
