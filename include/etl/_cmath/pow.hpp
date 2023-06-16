// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_POW_HPP
#define TETL_CMATH_POW_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, float exp) -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_powf)
        return __builtin_powf(base, exp);
#else
        return etl::detail::gcem::pow(base, exp);
#endif
    }
#if __has_builtin(__builtin_powf)
    return __builtin_powf(base, exp);
#else
    return etl::detail::gcem::pow(base, exp);
#endif
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powf(float base, float exp) -> float { return etl::pow(base, exp); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, double exp) -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_pow)
        return __builtin_pow(base, exp);
#else
        return etl::detail::gcem::pow(base, exp);
#endif
    }
#if __has_builtin(__builtin_pow)
    return __builtin_pow(base, exp);
#else
    return etl::detail::gcem::pow(base, exp);
#endif
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, long double exp) -> long double
{
    return detail::gcem::pow(base, exp);
}

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto powl(long double base, long double exp) -> long double { return etl::pow(base, exp); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(float base, int iexp) -> float { return etl::pow(base, static_cast<float>(iexp)); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(double base, int iexp) -> double { return etl::pow(base, static_cast<double>(iexp)); }

/// \brief Computes the value of base raised to the power exp
/// https://en.cppreference.com/w/cpp/numeric/math/pow
[[nodiscard]] constexpr auto pow(long double base, int iexp) -> long double
{
    return etl::pow(base, static_cast<long double>(iexp));
}

} // namespace etl

#endif // TETL_CMATH_POW_HPP
