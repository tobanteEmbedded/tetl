// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FMAX_HPP
#define TETL_CMATH_FMAX_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct fmax {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_fmaxf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_fmaxf(x, y);
            }
#endif
#if __has_builtin(__builtin_fmax)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_fmax(x, y);
            }
#endif
        }
        return etl::detail::gcem::max(x, y);
    }
} fmax;

} // namespace detail

/// \ingroup cmath
/// @{

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmax
[[nodiscard]] constexpr auto fmax(float x, float y) noexcept -> float
{
    return etl::detail::fmax(x, y);
}

[[nodiscard]] constexpr auto fmaxf(float x, float y) noexcept -> float
{
    return etl::detail::fmax(x, y);
}

[[nodiscard]] constexpr auto fmax(double x, double y) noexcept -> double
{
    return etl::detail::fmax(x, y);
}

[[nodiscard]] constexpr auto fmax(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmax(x, y);
}

[[nodiscard]] constexpr auto fmaxl(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmax(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FMAX_HPP
