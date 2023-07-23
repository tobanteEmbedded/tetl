// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_ARG_HPP
#define TETL_COMPLEX_ARG_HPP

#include "etl/_cmath/atan2.hpp"
#include "etl/_complex/complex.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto arg(complex<T> const& z) noexcept -> T
{
    return atan2(z.real(), z.imag());
}

template <typename Float>
[[nodiscard]] constexpr auto arg(Float f) noexcept -> enable_if_t<is_floating_point_v<Float>, complex<Float>>
{
    return arg(complex<Float>(f));
}

template <typename Integer>
[[nodiscard]] constexpr auto arg(Integer i) noexcept -> enable_if_t<is_integral_v<Integer>, complex<double>>
{
    return arg(complex<double>(i));
}

} // namespace etl

#endif // TETL_COMPLEX_ARG_HPP
