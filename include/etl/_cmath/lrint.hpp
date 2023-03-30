// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_CMATH_LRINT_HPP
#define TETL_CMATH_LRINT_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {
template <typename T, typename U>
[[nodiscard]] constexpr auto lrint_fallback(U arg) noexcept -> T
{
    return static_cast<T>(arg);
}

template <typename T>
[[nodiscard]] constexpr auto lrint_impl(T arg) noexcept -> long
{
    if (!is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_lrintf)
            return __builtin_lrintf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_lrint)
            return __builtin_lrint(arg);
#endif
        }
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_lrintl)
            return __builtin_lrintl(arg);
#endif
        }
    }
    return lrint_fallback<long>(arg);
}

template <typename T>
[[nodiscard]] constexpr auto llrint_impl(T arg) noexcept -> long long
{
    if (!is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_llrintf)
            return __builtin_llrintf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_llrint)
            return __builtin_llrint(arg);
#endif
        }
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_llrintl)
            return __builtin_llrintl(arg);
#endif
        }
    }
    return lrint_fallback<long long>(arg);
}

} // namespace detail

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto lrint(float arg) noexcept -> long { return detail::lrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto lrintf(float arg) noexcept -> long { return detail::lrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto lrint(double arg) noexcept -> long { return detail::lrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto lrint(long double arg) noexcept -> long { return detail::lrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto lrintl(long double arg) noexcept -> long { return detail::lrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
template <integral T>
[[nodiscard]] constexpr auto lrint(T arg) noexcept -> long
{
    return lrint(static_cast<double>(arg));
}

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto llrint(float arg) noexcept -> long long { return detail::llrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto llrintf(float arg) noexcept -> long long { return detail::llrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto llrint(double arg) noexcept -> long long { return detail::llrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto llrint(long double arg) noexcept -> long long { return detail::llrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
[[nodiscard]] constexpr auto llrintl(long double arg) noexcept -> long long { return detail::llrint_impl(arg); }

/// Rounds the floating-point argument arg to an integer value, using the current rounding mode.
template <integral T>
[[nodiscard]] constexpr auto llrint(T arg) noexcept -> long long
{
    return llrint(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LRINT_HPP
