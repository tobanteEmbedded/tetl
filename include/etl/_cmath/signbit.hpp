// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CMATH_SIGNBIT_HPP
#define TETL_CMATH_SIGNBIT_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

template <typename T>
[[nodiscard]] constexpr auto signbit_fallback(T arg) noexcept -> bool
{
    return arg == T(-0.0) || arg < T(0);
}

} // namespace detail

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
///
/// \ingroup cmath
[[nodiscard]] constexpr auto signbit(float arg) noexcept -> bool
{
    if (is_constant_evaluated()) {
        return detail::signbit_fallback(arg);
    }
#if __has_builtin(__builtin_signbit) and not defined(TETL_COMPILER_CLANG)
    return __builtin_signbit(arg);
#else
    return detail::signbit_fallback(arg);
#endif
}

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
///
/// \ingroup cmath
[[nodiscard]] constexpr auto signbit(double arg) noexcept -> bool
{
    if (is_constant_evaluated()) {
        return detail::signbit_fallback(arg);
    }
#if __has_builtin(__builtin_signbit) and not defined(TETL_COMPILER_CLANG)
    return __builtin_signbit(arg);
#else
    return detail::signbit_fallback(arg);
#endif
}

/// Determines if the given floating point number arg is negative.
///
/// This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
///
/// \ingroup cmath
[[nodiscard]] constexpr auto signbit(long double arg) noexcept -> bool
{
    if (is_constant_evaluated()) {
        return detail::signbit_fallback(arg);
    }
#if __has_builtin(__builtin_signbit) and not defined(TETL_COMPILER_CLANG)
    return __builtin_signbit(arg);
#else
    return detail::signbit_fallback(arg);
#endif
}

} // namespace etl

#endif // TETL_CMATH_SIGNBIT_HPP
