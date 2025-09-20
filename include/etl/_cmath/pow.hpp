// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_POW_HPP
#define TETL_CMATH_POW_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct pow {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float base, Float exponent) const noexcept -> Float
    {
        if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_powf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_powf(base, exponent);
            }
#endif
#if __has_constexpr_builtin(__builtin_pow)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_pow(base, exponent);
            }
#endif
        } else {
#if __has_builtin(__builtin_powf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_powf(base, exponent);
            }
#endif
#if __has_builtin(__builtin_pow)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_pow(base, exponent);
            }
#endif
        }

        return etl::detail::gcem::pow(base, exponent);
    }
} pow;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, float exp) -> float
{
    return etl::detail::pow(base, exp);
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powf(float base, float exp) -> float
{
    return etl::detail::pow(base, exp);
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, double exp) -> double
{
    return etl::detail::pow(base, exp);
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, long double exp) -> long double
{
    return etl::detail::pow(base, exp);
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powl(long double base, long double exp) -> long double
{
    return etl::detail::pow(base, exp);
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, int iexp) -> float
{
    return etl::detail::pow(base, static_cast<float>(iexp));
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, int iexp) -> double
{
    return etl::detail::pow(base, static_cast<double>(iexp));
}

/// Computes the value of base raised to the power exp
/// \details https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, int iexp) -> long double
{
    return etl::detail::pow(base, static_cast<long double>(iexp));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_POW_HPP
