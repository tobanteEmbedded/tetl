// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FLOOR_HPP
#define TETL_CMATH_FLOOR_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct floor {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_floorf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_floorf(arg);
            }
#endif
#if __has_builtin(__builtin_floor)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_floor(arg);
            }
#endif
        }
        return etl::detail::gcem::floor(arg);
    }
} floor;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floor(float arg) noexcept -> float
{
    return etl::detail::floor(arg);
}
[[nodiscard]] constexpr auto floorf(float arg) noexcept -> float
{
    return etl::detail::floor(arg);
}
[[nodiscard]] constexpr auto floor(double arg) noexcept -> double
{
    return etl::detail::floor(arg);
}
[[nodiscard]] constexpr auto floor(long double arg) noexcept -> long double
{
    return etl::detail::gcem::floor(arg);
}
[[nodiscard]] constexpr auto floorl(long double arg) noexcept -> long double
{
    return etl::detail::floor(arg);
}
[[nodiscard]] constexpr auto floor(integral auto arg) noexcept -> double
{
    return etl::detail::floor(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FLOOR_HPP
