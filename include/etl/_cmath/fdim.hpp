// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_FDIM_HPP
#define TETL_CMATH_FDIM_HPP

#include <etl/_cmath/fmax.hpp>

namespace etl {

/// \brief Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdim(float x, float y) noexcept -> float { return etl::fmax(x - y, 0); }

/// \brief Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdimf(float x, float y) noexcept -> float { return etl::fmax(x - y, 0); }

/// \brief Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdim(double x, double y) noexcept -> double { return etl::fmax(x - y, 0); }

/// \brief Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdim(long double x, long double y) noexcept -> long double { return etl::fmax(x - y, 0); }

/// \brief Returns the positive difference between x and y, that is, if x>y,
/// returns x-y, otherwise (if x≤y), returns +0.
///
/// \details https://en.cppreference.com/w/cpp/numeric/math/fdim
[[nodiscard]] constexpr auto fdiml(long double x, long double y) noexcept -> long double { return etl::fmax(x - y, 0); }

} // namespace etl

#endif // TETL_CMATH_FDIM_HPP
