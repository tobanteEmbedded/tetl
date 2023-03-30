/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
[[nodiscard]] constexpr auto round_impl(T arg) noexcept -> T
{
    if (!is_constant_evaluated()) {
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
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_roundl)
            return __builtin_roundl(arg);
#endif
        }
    }
    return detail::gcem::round(arg);
}
} // namespace detail

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(float arg) noexcept -> float { return detail::round_impl(arg); }

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto roundf(float arg) noexcept -> float { return detail::round_impl(arg); }

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(double arg) noexcept -> double { return detail::round_impl(arg); }

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto round(long double arg) noexcept -> long double { return detail::round_impl(arg); }

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
[[nodiscard]] constexpr auto roundl(long double arg) noexcept -> long double { return detail::round_impl(arg); }

/// \brief Computes the nearest integer value to arg (in floating-point format),
/// rounding halfway cases away from zero, regardless of the current rounding
/// mode.
///
/// https://en.cppreference.com/w/cpp/numeric/math/round
template <integral T>
[[nodiscard]] constexpr auto round(T arg) noexcept -> double
{
    return detail::round_impl(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ROUND_HPP
