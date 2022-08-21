/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FMA_HPP
#define TETL_CMATH_FMA_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/is_constant_evaluated.hpp"

namespace etl {

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto fma_fallback(T x, T y, T z) noexcept -> T
{
    return (x * y) + z;
}
} // namespace detail

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(float x, float y, float z) noexcept -> float
{
    if (is_constant_evaluated()) { return detail::fma_fallback(x, y, z); }
#if __has_builtin(__builtin_fmaf)
    return __builtin_fmaf(x, y, z);
#else
    return detail::fma_fallback(x, y, z);
#endif
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmaf(float x, float y, float z) noexcept -> float
{
    if (is_constant_evaluated()) { return detail::fma_fallback(x, y, z); }
#if __has_builtin(__builtin_fmaf)
    return __builtin_fmaf(x, y, z);
#else
    return detail::fma_fallback(x, y, z);
#endif
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(double x, double y, double z) noexcept -> double
{
    if (is_constant_evaluated()) { return detail::fma_fallback(x, y, z); }
#if __has_builtin(__builtin_fma)
    return __builtin_fma(x, y, z);
#else
    return detail::fma_fallback(x, y, z);
#endif
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(long double x, long double y, long double z) noexcept -> long double
{
    if (is_constant_evaluated()) { return detail::fma_fallback(x, y, z); }
#if __has_builtin(__builtin_fmal)
    return __builtin_fmal(x, y, z);
#else
    return detail::fma_fallback(x, y, z);
#endif
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmal(long double x, long double y, long double z) noexcept -> long double
{
    if (is_constant_evaluated()) { return detail::fma_fallback(x, y, z); }
#if __has_builtin(__builtin_fmal)
    return __builtin_fmal(x, y, z);
#else
    return detail::fma_fallback(x, y, z);
#endif
}

} // namespace etl

#endif // TETL_CMATH_FMA_HPP
