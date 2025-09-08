// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_LGAMMA_HPP
#define TETL_CMATH_LGAMMA_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

namespace detail {

inline constexpr struct lgamma {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_lgammaf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_lgammaf(arg);
            }
#endif
#if __has_builtin(__builtin_lgamma)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_lgamma(arg);
            }
#endif
        }
        return etl::detail::gcem::lgamma(arg);
    }
} lgamma;

} // namespace detail

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(float arg) noexcept -> float
{
    return etl::detail::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgammaf(float arg) noexcept -> float
{
    return etl::detail::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(double arg) noexcept -> double
{
    return etl::detail::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgamma(long double arg) noexcept -> long double
{
    return etl::detail::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
[[nodiscard]] constexpr auto lgammal(long double arg) noexcept -> long double
{
    return etl::detail::lgamma(arg);
}

/// Computes the natural logarithm of the absolute value of the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/lgamma
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto lgamma(T arg) noexcept -> double
{
    return etl::detail::lgamma(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LGAMMA_HPP
