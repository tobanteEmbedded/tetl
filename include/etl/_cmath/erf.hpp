// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_ERF_HPP
#define TETL_CMATH_ERF_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct erf {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
#if not(defined(__AVR__) and defined(__clang__))
        if (not is_constant_evaluated()) {
    #if __has_builtin(__builtin_erff)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_erff(arg);
            }
    #endif
    #if __has_builtin(__builtin_erf)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_erf(arg);
            }
    #endif
        }
#endif
        return etl::detail::gcem::erf(arg);
    }
} erf;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the error function of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/erf
[[nodiscard]] constexpr auto erf(float arg) noexcept -> float
{
    return etl::detail::erf(arg);
}
[[nodiscard]] constexpr auto erff(float arg) noexcept -> float
{
    return etl::detail::erf(arg);
}
[[nodiscard]] constexpr auto erf(double arg) noexcept -> double
{
    return etl::detail::erf(arg);
}
[[nodiscard]] constexpr auto erf(long double arg) noexcept -> long double
{
    return etl::detail::erf(arg);
}
[[nodiscard]] constexpr auto erfl(long double arg) noexcept -> long double
{
    return etl::detail::erf(arg);
}
[[nodiscard]] constexpr auto erf(integral auto arg) noexcept -> double
{
    return etl::detail::erf(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ERF_HPP
