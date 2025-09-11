// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MATH_ABS_HPP
#define TETL_MATH_ABS_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {
namespace detail {

inline constexpr struct abs {
    template <typename T>
    [[nodiscard]] constexpr auto operator()(T arg) const noexcept -> T
    {
        if (arg >= T(0)) {
            return arg;
        }
        return arg * T(-1);
    }
} abs;

inline constexpr struct fabs {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_fabsf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_fabsf(arg);
            }
#endif
#if __has_builtin(__builtin_fabs)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_fabs(arg);
            }
#endif
        }
        return etl::detail::abs(arg);
    }
} fabs;

} // namespace detail

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
[[nodiscard]] constexpr auto abs(int arg) noexcept -> int
{
    return etl::detail::abs(arg);
}

[[nodiscard]] constexpr auto abs(long arg) noexcept -> long
{
    return etl::detail::abs(arg);
}

[[nodiscard]] constexpr auto abs(long long arg) noexcept -> long long
{
    return etl::detail::abs(arg);
}

[[nodiscard]] constexpr auto abs(float arg) noexcept -> float
{
    return etl::detail::abs(arg);
}

[[nodiscard]] constexpr auto abs(double arg) noexcept -> double
{
    return etl::detail::abs(arg);
}

[[nodiscard]] constexpr auto abs(long double arg) noexcept -> long double
{
    return etl::detail::abs(arg);
}

} // namespace etl

#endif // TETL_MATH_ABS_HPP
