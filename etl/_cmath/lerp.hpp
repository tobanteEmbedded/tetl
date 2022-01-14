/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_LERP_HPP
#define TETL_CMATH_LERP_HPP

#include "etl/_math/lerp.hpp"

namespace etl {

/// \brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
/// the parameter t (or extrapolation, when t is outside the range [0,1]).
///
/// https://en.cppreference.com/w/cpp/numeric/lerp
[[nodiscard]] constexpr auto lerp(float a, float b, float t) noexcept -> float
{
    return detail::lerp_impl<float>(a, b, t);
}

[[nodiscard]] constexpr auto lerp(double a, double b, double t) noexcept -> double
{
    return detail::lerp_impl<double>(a, b, t);
}

[[nodiscard]] constexpr auto lerp(long double a, long double b, long double t) noexcept -> long double
{
    return detail::lerp_impl<long double>(a, b, t);
}
} // namespace etl

#endif // TETL_CMATH_LERP_HPP