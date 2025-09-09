// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_SQRT_HPP
#define TETL_CMATH_SQRT_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>

namespace etl {

namespace detail {

inline constexpr struct sqrt {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_sqrtf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_sqrtf(arg);
            }
#endif
#if __has_builtin(__builtin_sqrt)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_sqrt(arg);
            }
#endif
        }
        return etl::detail::gcem::sqrt(arg);
    }
} sqrt;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(float arg) noexcept -> float
{
    return etl::detail::sqrt(arg);
}

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrtf(float arg) noexcept -> float
{
    return etl::detail::sqrt(arg);
}

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(double arg) noexcept -> double
{
    return etl::detail::sqrt(arg);
}

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrt(long double arg) noexcept -> long double
{
    return etl::detail::sqrt(arg);
}

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
[[nodiscard]] constexpr auto sqrtl(long double arg) noexcept -> long double
{
    return etl::detail::sqrt(arg);
}

/// Computes the square root of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/sqrt
template <integral T>
[[nodiscard]] constexpr auto sqrt(T arg) noexcept -> double
{
    return etl::detail::sqrt(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_SQRT_HPP
