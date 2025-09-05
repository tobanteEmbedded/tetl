// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_HYPOT_HPP
#define TETL_CMATH_HYPOT_HPP

#include <etl/_config/all.hpp>

#include <etl/_cmath/isinf.hpp>
#include <etl/_cmath/isnan.hpp>
#include <etl/_cmath/sqrt.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

namespace detail {

inline constexpr struct hypot {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y) const noexcept -> Float
    {
        if (etl::isinf(x) or etl::isinf(y)) {
            return etl::numeric_limits<Float>::infinity();
        }
        if (etl::isnan(x) or etl::isnan(y)) {
            return etl::numeric_limits<Float>::quiet_NaN();
        }
        return etl::sqrt(x * x + y * y);
    }

    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y, Float z) const noexcept -> Float
    {
        if (etl::isinf(x) or etl::isinf(y) or etl::isinf(z)) {
            return etl::numeric_limits<Float>::infinity();
        }
        if (etl::isnan(x) or etl::isnan(y) or etl::isnan(z)) {
            return etl::numeric_limits<Float>::quiet_NaN();
        }
        return etl::sqrt(x * x + y * y + z * z);
    }

} hypot;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the square root of the sum of the squares of x and y,
/// without undue overflow or underflow at intermediate stages of the
/// computation.
///
/// - hypot(x,y) is INF if x or y is +INF or -INF; else
/// - hypot(x,y) is NAN if x or y is NAN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/hypot
[[nodiscard]] constexpr auto hypot(float x, float y) noexcept -> float
{
    return etl::detail::hypot(x, y);
}

[[nodiscard]] constexpr auto hypotf(float x, float y) noexcept -> float
{
    return etl::detail::hypot(x, y);
}

[[nodiscard]] constexpr auto hypot(double x, double y) noexcept -> double
{
    return etl::detail::hypot(x, y);
}

[[nodiscard]] constexpr auto hypot(long double x, long double y) noexcept -> long double
{
    return etl::detail::hypot(x, y);
}

[[nodiscard]] constexpr auto hypotl(long double x, long double y) noexcept -> long double
{
    return etl::detail::hypot(x, y);
}

[[nodiscard]] constexpr auto hypot(float x, float y, float z) noexcept -> float
{
    return etl::detail::hypot(x, y, z);
}

[[nodiscard]] constexpr auto hypot(double x, double y, double z) noexcept -> double
{
    return etl::detail::hypot(x, y, z);
}

[[nodiscard]] constexpr auto hypot(long double x, long double y, long double z) noexcept -> long double
{
    return etl::detail::hypot(x, y, z);
}

/// @}

} // namespace etl

#endif // TETL_CMATH_HYPOT_HPP
