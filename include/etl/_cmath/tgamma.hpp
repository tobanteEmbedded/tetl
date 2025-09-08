// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_TGAMMA_HPP
#define TETL_CMATH_TGAMMA_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

namespace detail {

inline constexpr struct tgamma {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_tgammaf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_tgammaf(arg);
            }
#endif
#if __has_builtin(__builtin_tgamma)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_tgamma(arg);
            }
#endif
        }
        return etl::detail::gcem::tgamma(arg);
    }
} tgamma;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the gamma function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgamma(float arg) noexcept -> float
{
    return etl::detail::tgamma(arg);
}
[[nodiscard]] constexpr auto tgammaf(float arg) noexcept -> float
{
    return etl::detail::tgamma(arg);
}
[[nodiscard]] constexpr auto tgamma(double arg) noexcept -> double
{
    return etl::detail::tgamma(arg);
}
[[nodiscard]] constexpr auto tgamma(long double arg) noexcept -> long double
{
    return etl::detail::tgamma(arg);
}
[[nodiscard]] constexpr auto tgammal(long double arg) noexcept -> long double
{
    return etl::detail::tgamma(arg);
}
[[nodiscard]] constexpr auto tgamma(integral auto arg) noexcept -> double
{
    return etl::detail::tgamma(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_TGAMMA_HPP
