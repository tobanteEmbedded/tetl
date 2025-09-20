// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ATANH_HPP
#define TETL_CMATH_ATANH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct atanh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
#if not defined(__AVR__)
        if (not is_constant_evaluated()) {
    #if __has_builtin(__builtin_atanhf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_atanhf(arg);
            }
    #endif
    #if __has_builtin(__builtin_atanh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_atanh(arg);
            }
    #endif
        }
#endif
        return etl::detail::gcem::atanh(arg);
    }
} atanh;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the inverse hyperbolic tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanh(float arg) noexcept -> float
{
    return etl::detail::atanh(arg);
}
[[nodiscard]] constexpr auto atanhf(float arg) noexcept -> float
{
    return etl::detail::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(double arg) noexcept -> double
{
    return etl::detail::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(long double arg) noexcept -> long double
{
    return etl::detail::atanh(arg);
}
[[nodiscard]] constexpr auto atanhl(long double arg) noexcept -> long double
{
    return etl::detail::atanh(arg);
}
[[nodiscard]] constexpr auto atanh(integral auto arg) noexcept -> double
{
    return etl::detail::atanh(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ATANH_HPP
