// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_POW_HPP
#define TETL_CMATH_POW_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, float exp) -> float { return detail::gcem::pow(base, exp); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powf(float base, float exp) -> float { return detail::gcem::pow(base, exp); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, double exp) -> double { return detail::gcem::pow(base, exp); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, long double exp) -> long double
{
    return detail::gcem::pow(base, exp);
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powl(long double base, long double exp) -> long double
{
    return detail::gcem::pow(base, exp);
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, int iexp) -> float
{
    return detail::gcem::pow(base, static_cast<float>(iexp));
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, int iexp) -> double
{
    return detail::gcem::pow(base, static_cast<double>(iexp));
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, int iexp) -> long double
{
    return detail::gcem::pow(base, static_cast<long double>(iexp));
}

} // namespace etl

#endif // TETL_CMATH_POW_HPP
