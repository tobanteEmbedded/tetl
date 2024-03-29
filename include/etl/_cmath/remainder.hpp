// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_REMAINDER_HPP
#define TETL_CMATH_REMAINDER_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>

namespace etl {

/// \brief Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(float x, float y) noexcept -> float { return etl::detail::gcem::fmod(x, y); }

/// \brief Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainderf(float x, float y) noexcept -> float { return etl::detail::gcem::fmod(x, y); }

/// \brief Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(double x, double y) noexcept -> double { return etl::detail::gcem::fmod(x, y); }

/// \brief Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainder(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::fmod(x, y);
}

/// \brief Computes the remainder of the floating point division operation x/y.
/// \details https://en.cppreference.com/w/cpp/numeric/math/remainder
[[nodiscard]] constexpr auto remainderl(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::fmod(x, y);
}

} // namespace etl

#endif // TETL_CMATH_REMAINDER_HPP
