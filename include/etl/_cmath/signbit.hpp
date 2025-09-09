// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CMATH_SIGNBIT_HPP
#define TETL_CMATH_SIGNBIT_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

template <typename T>
[[nodiscard]] constexpr auto signbit_fallback(T arg) noexcept -> bool
{
    return arg == T(-0.0) or arg < T(0);
}

template <typename T>
[[nodiscard]] constexpr auto signbit(T arg) noexcept -> bool
{
    if (not is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_signbitf)
            return __builtin_signbitf(arg);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_signbit)
            return __builtin_signbit(arg);
#endif
        }
    }
    return signbit_fallback(arg);
}

} // namespace detail

/// \ingroup cmath
/// @{

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(float arg) noexcept -> bool
{
    return etl::detail::signbit(arg);
}

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(double arg) noexcept -> bool
{
    return etl::detail::signbit(arg);
}

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(long double arg) noexcept -> bool
{
    return etl::detail::signbit(arg);
}

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(integral auto arg) noexcept -> bool
{
    return etl::detail::signbit(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_SIGNBIT_HPP
