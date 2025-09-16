// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CMATH_FMOD_HPP
#define TETL_CMATH_FMOD_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct fmod {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_fmodf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_fmodf(x, y);
            }
#endif
#if __has_builtin(__builtin_fmod)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_fmod(x, y);
            }
#endif
        }
        return etl::detail::gcem::fmod(x, y);
    }
} fmod;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the floating-point remainder of the division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmod(float x, float y) noexcept -> float
{
    return etl::detail::fmod(x, y);
}
[[nodiscard]] constexpr auto fmodf(float x, float y) noexcept -> float
{
    return etl::detail::fmod(x, y);
}
[[nodiscard]] constexpr auto fmod(double x, double y) noexcept -> double
{
    return etl::detail::fmod(x, y);
}
[[nodiscard]] constexpr auto fmod(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmod(x, y);
}
[[nodiscard]] constexpr auto fmodl(long double x, long double y) noexcept -> long double
{
    return etl::detail::fmod(x, y);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_FMOD_HPP
