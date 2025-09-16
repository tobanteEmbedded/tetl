// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_CEIL_HPP
#define TETL_CMATH_CEIL_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct ceil {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_ceilf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_ceilf(arg);
            }
#endif
#if __has_builtin(__builtin_ceil)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_ceil(arg);
            }
#endif
        }
        return etl::detail::gcem::ceil(arg);
    }
} ceil;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the smallest integer value not less than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/ceil
[[nodiscard]] constexpr auto ceil(float arg) noexcept -> float
{
    return etl::detail::ceil(arg);
}
[[nodiscard]] constexpr auto ceilf(float arg) noexcept -> float
{
    return etl::detail::ceil(arg);
}
[[nodiscard]] constexpr auto ceil(double arg) noexcept -> double
{
    return etl::detail::ceil(arg);
}
[[nodiscard]] constexpr auto ceil(long double arg) noexcept -> long double
{
    return etl::detail::ceil(arg);
}
[[nodiscard]] constexpr auto ceill(long double arg) noexcept -> long double
{
    return etl::detail::ceil(arg);
}
[[nodiscard]] constexpr auto ceil(integral auto arg) noexcept -> double
{
    return etl::detail::ceil(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_CEIL_HPP
