
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FLOOR_HPP
#define TETL_CMATH_FLOOR_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

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
template <typename T>
[[nodiscard]] constexpr auto floor(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::floor(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_FLOOR_HPP
