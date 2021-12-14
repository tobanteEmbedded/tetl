/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_TRUNC_HPP
#define TETL_CMATH_TRUNC_HPP

#include "etl/_config/all.hpp"

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_constant_evaluated.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto trunc_impl(T arg) noexcept -> T
{
    if (!is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_truncf)
            return __builtin_truncf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_trunc)
            return __builtin_trunc(arg);
#endif
        }
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_truncl)
            return __builtin_truncl(arg);
#endif
        }
    }
    return detail::gcem::trunc(arg);
}
} // namespace detail

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(float arg) noexcept -> float { return detail::trunc_impl(arg); }

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto truncf(float arg) noexcept -> float { return detail::trunc_impl(arg); }

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(double arg) noexcept -> double { return detail::trunc_impl(arg); }

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto trunc(long double arg) noexcept -> long double { return detail::trunc_impl(arg); }

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
[[nodiscard]] constexpr auto truncl(long double arg) noexcept -> long double { return detail::trunc_impl(arg); }

/// \brief Computes the nearest integer not greater in magnitude than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/trunc
template <typename T>
[[nodiscard]] constexpr auto trunc(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return detail::trunc_impl(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TRUNC_HPP