// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ATAN2_HPP
#define TETL_CMATH_ATAN2_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct atan2 {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_atan2f)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_atan2f(x, y);
            }
#endif
#if __has_builtin(__builtin_atan2)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_atan2(x, y);
            }
#endif
        }
        return etl::detail::gcem::atan2(x, y);
    }
} atan2;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the arc tangent of y/x using the signs of arguments to determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
[[nodiscard]] constexpr auto atan2(float x, float y) noexcept -> float
{
    return etl::detail::atan2(x, y);
}

[[nodiscard]] constexpr auto atan2f(float x, float y) noexcept -> float
{
    return etl::detail::atan2(x, y);
}

[[nodiscard]] constexpr auto atan2(double x, double y) noexcept -> double
{
    return etl::detail::atan2(x, y);
}

[[nodiscard]] constexpr auto atan2(long double x, long double y) noexcept -> long double
{
    return etl::detail::atan2(x, y);
}

[[nodiscard]] constexpr auto atan2l(long double x, long double y) noexcept -> long double
{
    return etl::detail::atan2(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ATAN2_HPP
