/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_BETA_HPP
#define TETL_CMATH_BETA_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the beta function of x and y.
/// https://en.cppreference.com/w/cpp/numeric/special_functions/beta
[[nodiscard]] constexpr auto beta(double x, double y) noexcept -> double { return etl::detail::gcem::beta(x, y); }

/// \brief Computes the beta function of x and y.
/// https://en.cppreference.com/w/cpp/numeric/special_functions/beta
[[nodiscard]] constexpr auto betaf(float x, float y) noexcept -> float { return etl::detail::gcem::beta(x, y); }

/// \brief Computes the beta function of x and y.
/// https://en.cppreference.com/w/cpp/numeric/special_functions/beta
[[nodiscard]] constexpr auto betal(long double x, long double y) noexcept -> long double
{
    return etl::detail::gcem::beta(x, y);
}

} // namespace etl

#endif // TETL_CMATH_BETA_HPP