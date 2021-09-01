/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_HYPOT_HPP
#define TETL_CMATH_HYPOT_HPP

#include "etl/_config/all.hpp"

#include "etl/_cmath/isinf.hpp"
#include "etl/_cmath/isnan.hpp"
#include "etl/_cmath/sqrt.hpp"

namespace etl {

/// \brief Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypot(float x, float y) noexcept -> float
{
    if (etl::isinf(x) || etl::isinf(x)) { return TETL_BUILTIN_HUGE_VALF; }
    if (etl::isnan(x) || etl::isnan(x)) { return TETL_BUILTIN_NANF; }
    return etl::sqrt(x * x + y * y);
}

/// \brief Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypotf(float x, float y) noexcept -> float
{
    if (etl::isinf(x) || etl::isinf(x)) { return TETL_BUILTIN_HUGE_VALF; }
    if (etl::isnan(x) || etl::isnan(x)) { return TETL_BUILTIN_NANF; }
    return etl::sqrt(x * x + y * y);
}

/// \brief Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypot(double x, double y) noexcept -> double
{
    if (etl::isinf(x) || etl::isinf(x)) { return TETL_BUILTIN_HUGE_VAL; }
    if (etl::isnan(x) || etl::isnan(x)) { return TETL_BUILTIN_NAN; }
    return etl::sqrt(x * x + y * y);
}

/// \brief Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypot(long double x, long double y) noexcept
    -> long double
{
    if (etl::isinf(x) || etl::isinf(x)) { return TETL_BUILTIN_HUGE_VALL; }
    if (etl::isnan(x) || etl::isnan(x)) { return TETL_BUILTIN_NANL; }
    return etl::sqrt(x * x + y * y);
}

/// \brief Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypotl(long double x, long double y) noexcept
    -> long double
{
    if (etl::isinf(x) || etl::isinf(x)) { return TETL_BUILTIN_HUGE_VALL; }
    if (etl::isnan(x) || etl::isnan(x)) { return TETL_BUILTIN_NANL; }
    return etl::sqrt(x * x + y * y);
}

} // namespace etl

#endif // TETL_CMATH_HYPOT_HPP