// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FMIN_HPP
#define TETL_CMATH_FMIN_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>

namespace etl {

namespace detail {

inline constexpr struct fmin {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_fminf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_fminf(x, y);
            }
#endif
#if __has_builtin(__builtin_fmin)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_fmin(x, y);
            }
#endif
        }
        return etl::detail::gcem::min(x, y);
    }
} fmin;

} // namespace detail

/// \ingroup cmath
/// @{

/// Returns the smaller of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// https://en.cppreference.com/w/cpp/numeric/math/fmin
[[nodiscard]] constexpr auto fmin(float x, float y) noexcept -> float
{
    return etl::detail::fmin(x, y);
}

[[nodiscard]] constexpr auto fminf(float x, float y) noexcept -> float
{
    return etl::detail::fmin(x, y);
}

[[nodiscard]] constexpr auto fmin(double x, double y) noexcept -> double
{
    return etl::detail::fmin(x, y);
}

[[nodiscard]] constexpr auto fmin(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmin(x, y);
}

[[nodiscard]] constexpr auto fminl(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmin(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FMIN_HPP
