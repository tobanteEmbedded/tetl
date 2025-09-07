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

template <typename T>
[[nodiscard]] constexpr auto round(T arg) noexcept -> T
{
    if (not is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_roundf)
            return __builtin_roundf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_round)
            return __builtin_round(arg);
#endif
        }
    }
    return detail::gcem::round(arg);
}

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
    return etl::detail::round(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ROUND_HPP
