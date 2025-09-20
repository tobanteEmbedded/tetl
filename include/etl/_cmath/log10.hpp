// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_CMATH_LOG10_HPP
#define TETL_CMATH_LOG10_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct log10 {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_log10f)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_log10f(arg);
            }
#endif
#if __has_builtin(__builtin_log10)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_log10(arg);
            }
#endif
        }
        return etl::detail::gcem::log(arg) / static_cast<Float>(GCEM_LOG_10);
    }
} log10;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
[[nodiscard]] constexpr auto log10(float arg) noexcept -> float
{
    return etl::detail::log10(arg);
}
[[nodiscard]] constexpr auto log10f(float arg) noexcept -> float
{
    return etl::detail::log10(arg);
}
[[nodiscard]] constexpr auto log10(double arg) noexcept -> double
{
    return etl::detail::log10(arg);
}
[[nodiscard]] constexpr auto log10(long double arg) noexcept -> long double
{
    return etl::detail::log10(arg);
}
[[nodiscard]] constexpr auto log10l(long double arg) noexcept -> long double
{
    return etl::detail::log10(arg);
}
[[nodiscard]] constexpr auto log10(integral auto arg) noexcept -> double
{
    return etl::detail::log10(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_LOG10_HPP
