// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ROUND_HPP
#define TETL_CMATH_ROUND_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {

inline constexpr struct round {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_roundf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_roundf(arg);
            }
#endif
#if __has_builtin(__builtin_round)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_round(arg);
            }
#endif
        }
        return etl::detail::gcem::round(arg);
    }
} round;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(float arg) noexcept -> float
{
    return etl::detail::round(arg);
}
[[nodiscard]] constexpr auto roundf(float arg) noexcept -> float
{
    return etl::detail::round(arg);
}
[[nodiscard]] constexpr auto round(double arg) noexcept -> double
{
    return etl::detail::round(arg);
}
[[nodiscard]] constexpr auto round(long double arg) noexcept -> long double
{
    return etl::detail::round(arg);
}
[[nodiscard]] constexpr auto roundl(long double arg) noexcept -> long double
{
    return etl::detail::round(arg);
}
[[nodiscard]] constexpr auto round(integral auto arg) noexcept -> double
{
    return etl::detail::round(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ROUND_HPP
