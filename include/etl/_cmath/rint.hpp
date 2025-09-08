// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
#ifndef TETL_CMATH_RINT_HPP
#define TETL_CMATH_RINT_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto rint_fallback(T arg) noexcept -> T
{
    if constexpr (sizeof(T) <= sizeof(long)) {
        return static_cast<T>(static_cast<long>(arg));
    } else {
        return static_cast<T>(static_cast<long long>(arg));
    }
}

template <typename T>
[[nodiscard]] constexpr auto rint_impl(T arg) noexcept -> T
{
    if (!is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_rintf)
            return __builtin_rintf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_rint)
            return __builtin_rint(arg);
#endif
        }
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_rintl)
            return __builtin_rintl(arg);
#endif
        }
    }
    return rint_fallback(arg);
}

} // namespace detail

/// \ingroup cmath
/// @{

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
[[nodiscard]] constexpr auto rint(float arg) noexcept -> float
{
    return detail::rint_impl(arg);
}

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
[[nodiscard]] constexpr auto rintf(float arg) noexcept -> float
{
    return detail::rint_impl(arg);
}

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
[[nodiscard]] constexpr auto rint(double arg) noexcept -> double
{
    return detail::rint_impl(arg);
}

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
[[nodiscard]] constexpr auto rint(long double arg) noexcept -> long double
{
    return detail::rint_impl(arg);
}

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
[[nodiscard]] constexpr auto rintl(long double arg) noexcept -> long double
{
    return detail::rint_impl(arg);
}

/// Rounds the floating-point argument arg to an integer value
/// (in floating-point format), using the current rounding mode.
template <integral T>
[[nodiscard]] constexpr auto rint(T arg) noexcept -> double
{
    return rint(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_RINT_HPP
