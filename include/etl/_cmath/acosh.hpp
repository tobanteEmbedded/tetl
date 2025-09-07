// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ACOSH_HPP
#define TETL_CMATH_ACOSH_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct acosh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
#if not defined(__AVR__)
        if (not is_constant_evaluated()) {
    #if __has_builtin(__builtin_acoshf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_acoshf(arg);
            }
    #endif
    #if __has_builtin(__builtin_acosh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_acosh(arg);
            }
    #endif
        }
#endif
        return etl::detail::gcem::acosh(arg);
    }
} acosh;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the inverse hyperbolic cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acosh
[[nodiscard]] constexpr auto acosh(float arg) noexcept -> float
{
    return etl::detail::acosh(arg);
}
[[nodiscard]] constexpr auto acoshf(float arg) noexcept -> float
{
    return etl::detail::acosh(arg);
}
[[nodiscard]] constexpr auto acosh(double arg) noexcept -> double
{
    return etl::detail::acosh(arg);
}
[[nodiscard]] constexpr auto acosh(long double arg) noexcept -> long double
{
    return etl::detail::acosh(arg);
}
[[nodiscard]] constexpr auto acoshl(long double arg) noexcept -> long double
{
    return etl::detail::acosh(arg);
}
[[nodiscard]] constexpr auto acosh(integral auto arg) noexcept -> double
{
    return etl::detail::acosh(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ACOSH_HPP
