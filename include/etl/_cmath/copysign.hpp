// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_COPYSIGN_HPP
#define TETL_CMATH_COPYSIGN_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/is_constant_evaluated.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
template <typename T>
constexpr auto copysign_fallback(T x, T y) noexcept -> T
{
    if ((x < 0 and y > 0) or (x > 0 and y < 0)) {
        return -x;
    }
    return x;
}

template <typename T>
[[nodiscard]] constexpr auto copysign_impl(T x, T y) noexcept -> T
{
    if (!is_constant_evaluated()) {
        if constexpr (is_same_v<T, float>) {
#if __has_builtin(__builtin_copysignf)
            return __builtin_copysignf(x, y);
#endif
        }
        if constexpr (is_same_v<T, double>) {
#if __has_builtin(__builtin_copysign)
            return __builtin_copysign(x, y);
#endif
        }
        if constexpr (is_same_v<T, long double>) {
#if __has_builtin(__builtin_copysignl)
            return __builtin_copysignl(x, y);
#endif
        }
    }
    return copysign_fallback(x, y);
}

} // namespace detail

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(float mag, float sgn) -> float { return detail::copysign_impl(mag, sgn); }

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignf(float mag, float sgn) -> float { return detail::copysign_impl(mag, sgn); }

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(double mag, double sgn) -> double { return detail::copysign_impl(mag, sgn); }

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(long double mag, long double sgn) -> long double
{
    return detail::copysign_impl(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignl(long double mag, long double sgn) -> long double
{
    return detail::copysign_impl(mag, sgn);
}

} // namespace etl

#endif // TETL_CMATH_COPYSIGN_HPP
