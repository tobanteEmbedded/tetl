// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CMATH_SIGNBIT_HPP
#define TETL_CMATH_SIGNBIT_HPP

#include <etl/_config/all.hpp>

#include <etl/_array/array.hpp>
#include <etl/_bit/bit_cast.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_cstdint/int_t.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

template <typename Float>
[[nodiscard]] constexpr auto signbit_fallback(Float arg) noexcept -> bool
{
    if constexpr (sizeof(Float) == 4) {
        auto const bits = etl::bit_cast<etl::int32_t>(arg);
        return bits < 0;
    } else if constexpr (sizeof(Float) == 8) {
        auto const bits = etl::bit_cast<etl::int64_t>(arg);
        return bits < 0;
    } else {
        return arg == Float(-0.0) or arg < Float(0);
    }
}

inline constexpr struct signbit {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> bool
    {
        if constexpr (is_same_v<Float, float>) {
#if __has_builtin(__builtin_signbitf)
            return __builtin_signbitf(arg);
#endif
        }
        if constexpr (is_same_v<Float, double>) {
#if __has_builtin(__builtin_signbit)
            return __builtin_signbit(arg);
#endif
        }
        if constexpr (is_same_v<Float, long double>) {
#if __has_builtin(__builtin_signbitl)
            return __builtin_signbitl(arg);
#endif
        }
        return signbit_fallback(arg);
    }
} signbit;

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
