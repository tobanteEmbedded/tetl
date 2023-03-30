
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_FLOOR_HPP
#define TETL_CMATH_FLOOR_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_concepts/integral.hpp"

namespace etl {

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floor(float arg) noexcept -> float { return etl::detail::gcem::floor(arg); }

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floorf(float arg) noexcept -> float { return etl::detail::gcem::floor(arg); }

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floor(double arg) noexcept -> double { return etl::detail::gcem::floor(arg); }

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floor(long double arg) noexcept -> long double { return etl::detail::gcem::floor(arg); }

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
[[nodiscard]] constexpr auto floorl(long double arg) noexcept -> long double { return etl::detail::gcem::floor(arg); }

/// \brief Computes the largest integer value not greater than arg.
/// https://en.cppreference.com/w/cpp/numeric/math/floor
template <integral T>
[[nodiscard]] constexpr auto floor(T arg) noexcept -> double
{
    return etl::detail::gcem::floor(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_FLOOR_HPP
