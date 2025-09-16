// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FDIM_HPP
#define TETL_CMATH_FDIM_HPP

#include <etl/_config/all.hpp>

#include <etl/_cmath/fmax.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct fdim {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_fdimf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_fdimf(x, y);
            }
#endif
#if __has_builtin(__builtin_fdim)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_fdim(x, y);
            }
#endif
        }
        return etl::fmax(x - y, static_cast<Float>(0));
    }
} fdim;

} // namespace detail

/// \ingroup cmath
/// @{

/// Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdim(float x, float y) noexcept -> float
{
    return etl::detail::fdim(x, y);
}
[[nodiscard]] constexpr auto fdimf(float x, float y) noexcept -> float
{
    return etl::detail::fdim(x, y);
}
[[nodiscard]] constexpr auto fdim(double x, double y) noexcept -> double
{
    return etl::detail::fdim(x, y);
}
[[nodiscard]] constexpr auto fdim(long double x, long double y) noexcept -> long double
{
    return etl::detail::fdim(x, y);
}
[[nodiscard]] constexpr auto fdiml(long double x, long double y) noexcept -> long double
{
    return etl::detail::fdim(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FDIM_HPP
