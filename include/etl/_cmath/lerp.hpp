// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LERP_HPP
#define TETL_CMATH_LERP_HPP

#include <etl/_concepts/floating_point.hpp>

namespace etl {

/// \brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
/// the parameter t (or extrapolation, when t is outside the range [0,1]).
///
/// \details https://en.cppreference.com/w/cpp/numeric/lerp
template <floating_point Float>
[[nodiscard]] constexpr auto lerp(Float a, Float b, Float t) noexcept -> Float
{
    if ((a <= 0 && b >= 0) || (a >= 0 && b <= 0)) {
        return t * b + (1 - t) * a;
    }

    if (t == 1) {
        return b;
    }

    auto const x = a + t * (b - a);
    if ((t > 1) == (b > a)) {
        return b < x ? x : b;
    }
    return x < b ? x : b;
}

} // namespace etl

#endif // TETL_CMATH_LERP_HPP
