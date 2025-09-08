// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_REMAINDER_HPP
#define TETL_CMATH_REMAINDER_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

namespace detail {

inline constexpr struct remainder {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_remainderf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_remainderf(x, y);
            }
#endif
#if __has_builtin(__builtin_remainder)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_remainder(x, y);
            }
#endif
        }
        return etl::detail::gcem::fmod(x, y);
    }
} remainder;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(float x, float y) noexcept -> float
{
    return etl::detail::remainder(x, y);
}

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainderf(float x, float y) noexcept -> float
{
    return etl::detail::remainder(x, y);
}

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(double x, double y) noexcept -> double
{
    return etl::detail::remainder(x, y);
}

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(long double x, long double y) noexcept -> long double
{
    return etl::detail::remainder(x, y);
}

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainderl(long double x, long double y) noexcept -> long double
{
    return etl::detail::remainder(x, y);
}

/// Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
template <integral Int>
[[nodiscard]] constexpr auto remainder(Int x, Int y) noexcept -> double
{
    return etl::detail::remainder(static_cast<double>(x), static_cast<double>(y));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_REMAINDER_HPP
