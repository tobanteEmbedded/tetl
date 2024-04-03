// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_FMAX_HPP
#define TETL_CMATH_FMAX_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>

namespace etl {

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmax
/// \ingroup cmath
[[nodiscard]] constexpr auto fmax(float x, float y) noexcept -> float { return etl::detail::gcem::max(x, y); }

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmax
/// \ingroup cmath
[[nodiscard]] constexpr auto fmaxf(float x, float y) noexcept -> float { return etl::detail::gcem::max(x, y); }

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmax
/// \ingroup cmath
[[nodiscard]] constexpr auto fmax(double x, double y) noexcept -> double { return etl::detail::gcem::max(x, y); }

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmax
/// \ingroup cmath
[[nodiscard]] constexpr auto fmax(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::max(x, y);
}

/// Returns the larger of two floating point arguments, treating NaNs as
/// missing data (between a NaN and a numeric value, the numeric value is
/// chosen)
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fmax
/// \ingroup cmath
[[nodiscard]] constexpr auto fmaxl(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::max(x, y);
}

} // namespace etl

#endif // TETL_CMATH_FMAX_HPP
