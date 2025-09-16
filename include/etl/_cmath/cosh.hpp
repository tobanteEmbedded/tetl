// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_COSH_HPP
#define TETL_CMATH_COSH_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct cosh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_coshf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_coshf(arg);
            }
#endif
#if __has_builtin(__builtin_cosh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_cosh(arg);
            }
#endif
        }
        return etl::detail::gcem::cosh(arg);
    }
} cosh;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the hyperbolic cosine of arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/cosh
[[nodiscard]] constexpr auto cosh(float arg) noexcept -> float
{
    return etl::detail::cosh(arg);
}
[[nodiscard]] constexpr auto coshf(float arg) noexcept -> float
{
    return etl::detail::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(double arg) noexcept -> double
{
    return etl::detail::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(long double arg) noexcept -> long double
{
    return etl::detail::cosh(arg);
}
[[nodiscard]] constexpr auto coshl(long double arg) noexcept -> long double
{
    return etl::detail::cosh(arg);
}
[[nodiscard]] constexpr auto cosh(integral auto arg) noexcept -> double
{
    return etl::detail::cosh(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_COSH_HPP
