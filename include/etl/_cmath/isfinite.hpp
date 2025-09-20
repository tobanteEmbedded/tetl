// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CMATH_ISFINITE_HPP
#define TETL_CMATH_ISFINITE_HPP

#include <etl/_cmath/isinf.hpp>
#include <etl/_cmath/isnan.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct isfinite {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> bool
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_isfinitef)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_isfinitef(arg);
            }
#endif
#if __has_builtin(__builtin_isfinite)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_isfinite(arg);
            }
#endif
        }
        return not etl::isnan(arg) and not etl::isinf(arg);
    }
} isfinite;

} // namespace detail

/// \ingroup cmath
/// @{

/// Determines if the given floating point number arg has finite value
/// i.e. it is normal, subnormal or zero, but not infinite or NaN.
/// \details https://en.cppreference.com/w/cpp/numeric/math/isfinite
[[nodiscard]] constexpr auto isfinite(float arg) -> bool
{
    return etl::detail::isfinite(arg);
}

[[nodiscard]] constexpr auto isfinite(double arg) -> bool
{
    return etl::detail::isfinite(arg);
}

[[nodiscard]] constexpr auto isfinite(long double arg) -> bool
{
    return etl::detail::isfinite(arg);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ISFINITE_HPP
