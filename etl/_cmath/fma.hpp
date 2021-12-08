/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FMA_HPP
#define TETL_CMATH_FMA_HPP

namespace etl {

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(float x, float y, float z) noexcept -> float { return (x * y) + z; }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmaf(float x, float y, float z) noexcept -> float { return (x * y) + z; }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(double x, double y, double z) noexcept -> double { return (x * y) + z; }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(long double x, long double y, long double z) noexcept -> long double
{
    return (x * y) + z;
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmal(long double x, long double y, long double z) noexcept -> long double
{
    return (x * y) + z;
}

} // namespace etl

#endif // TETL_CMATH_FMA_HPP