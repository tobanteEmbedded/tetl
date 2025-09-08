// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_LOG1P_HPP
#define TETL_CMATH_LOG1P_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

namespace detail {

inline constexpr struct log1p {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_log1pf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_log1pf(arg);
            }
#endif
#if __has_builtin(__builtin_log1p)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_log1p(arg);
            }
#endif
        }
        return etl::detail::gcem::log1p(arg);
    }
} log1p;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1p(float v) noexcept -> float
{
    return etl::detail::log1p(v);
}
[[nodiscard]] constexpr auto log1pf(float v) noexcept -> float
{
    return etl::detail::log1p(v);
}
[[nodiscard]] constexpr auto log1p(double v) noexcept -> double
{
    return etl::detail::log1p(v);
}
[[nodiscard]] constexpr auto log1p(long double v) noexcept -> long double
{
    return etl::detail::log1p(v);
}
[[nodiscard]] constexpr auto log1pl(long double v) noexcept -> long double
{
    return etl::detail::log1p(v);
}
[[nodiscard]] constexpr auto log1p(integral auto arg) noexcept -> double
{
    return etl::detail::log1p(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_LOG1P_HPP
