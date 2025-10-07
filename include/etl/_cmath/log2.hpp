// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_LOG2_HPP
#define TETL_CMATH_LOG2_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_cmath/log.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct log2 {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
#if not(defined(__AVR__) and defined(__clang__))
        if (not is_constant_evaluated()) {
    #if __has_builtin(__builtin_log2f)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_log2f(arg);
            }
    #endif
    #if __has_builtin(__builtin_log2)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_log2(arg);
            }
    #endif
        }
#endif
        return etl::log(arg) / static_cast<Float>(GCEM_LOG_2);
    }
} log2;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the binary (base-2) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(float arg) noexcept -> float
{
    return etl::detail::log2(arg);
}
[[nodiscard]] constexpr auto log2f(float arg) noexcept -> float
{
    return etl::detail::log2(arg);
}
[[nodiscard]] constexpr auto log2(double arg) noexcept -> double
{
    return etl::detail::log2(arg);
}
[[nodiscard]] constexpr auto log2(long double arg) noexcept -> long double
{
    return etl::detail::log2(arg);
}
[[nodiscard]] constexpr auto log2l(long double arg) noexcept -> long double
{
    return etl::detail::log2(arg);
}
[[nodiscard]] constexpr auto log2(integral auto arg) noexcept -> double
{
    return etl::detail::log2(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_LOG2_HPP
