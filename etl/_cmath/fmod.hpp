/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_FMOD_HPP
#define TETL_CMATH_FMOD_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the floating-point remainder of the division operation x/y.
/// https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmod(float x, float y) noexcept -> float
{
    return etl::detail::gcem::fmod(x, y);
}

/// \brief Computes the floating-point remainder of the division operation x/y.
/// https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmodf(float x, float y) noexcept -> float
{
    return etl::detail::gcem::fmod(x, y);
}

/// \brief Computes the floating-point remainder of the division operation x/y.
/// https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmod(double x, double y) noexcept -> double
{
    return etl::detail::gcem::fmod(x, y);
}

/// \brief Computes the floating-point remainder of the division operation x/y.
/// https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmod(long double x, long double y) noexcept
    -> long double
{
    return etl::detail::gcem::fmod(x, y);
}

/// \brief Computes the floating-point remainder of the division operation x/y.
/// https://en.cppreference.com/w/cpp/numeric/math/fmod
[[nodiscard]] constexpr auto fmodl(long double x, long double y) noexcept
    -> long double
{
    return etl::detail::gcem::fmod(x, y);
}

} // namespace etl

#endif // TETL_CMATH_FMOD_HPP