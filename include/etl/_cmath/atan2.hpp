// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ATAN2_HPP
#define TETL_CMATH_ATAN2_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>

namespace etl {

/// \brief Computes the arc tangent of y/x using the signs of arguments to
/// determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
/// \ingroup cmath
[[nodiscard]] constexpr auto atan2(float x, float y) noexcept -> float { return etl::detail::gcem::atan2(x, y); }

/// \brief Computes the arc tangent of y/x using the signs of arguments to
/// determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
/// \ingroup cmath
[[nodiscard]] constexpr auto atan2f(float x, float y) noexcept -> float { return etl::detail::gcem::atan2(x, y); }

/// \brief Computes the arc tangent of y/x using the signs of arguments to
/// determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
/// \ingroup cmath
[[nodiscard]] constexpr auto atan2(double x, double y) noexcept -> double { return etl::detail::gcem::atan2(x, y); }

/// \brief Computes the arc tangent of y/x using the signs of arguments to
/// determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
/// \ingroup cmath
[[nodiscard]] constexpr auto atan2(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::atan2(x, y);
}

/// \brief Computes the arc tangent of y/x using the signs of arguments to
/// determine the correct quadrant.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan2
/// \ingroup cmath
[[nodiscard]] constexpr auto atan2l(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::atan2(x, y);
}

} // namespace etl

#endif // TETL_CMATH_ATAN2_HPP
