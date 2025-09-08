// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_SINH_HPP
#define TETL_CMATH_SINH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

namespace detail {

inline constexpr struct sinh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_sinhf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_sinhf(arg);
            }
#endif
#if __has_builtin(__builtin_sinh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_sinh(arg);
            }
#endif
        }
        return etl::detail::gcem::sinh(arg);
    }
} sinh;

} // namespace detail

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
[[nodiscard]] constexpr auto sinh(float arg) noexcept -> float
{
    return etl::detail::sinh(arg);
}

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
[[nodiscard]] constexpr auto sinhf(float arg) noexcept -> float
{
    return etl::detail::sinh(arg);
}

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
[[nodiscard]] constexpr auto sinh(double arg) noexcept -> double
{
    return etl::detail::sinh(arg);
}

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
[[nodiscard]] constexpr auto sinh(long double arg) noexcept -> long double
{
    return etl::detail::sinh(arg);
}

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
[[nodiscard]] constexpr auto sinhl(long double arg) noexcept -> long double
{
    return etl::detail::sinh(arg);
}

/// Computes the hyperbolic sine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/sinh
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto sinh(T arg) noexcept -> double
{
    return etl::detail::sinh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_SINH_HPP
