// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_CONJ_HPP
#define TETL_COMPLEX_CONJ_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto conj(complex<T> const& z) noexcept -> complex<T>
{
    return complex<T>(z.real(), -z.imag());
}

template <typename Float>
[[nodiscard]] constexpr auto conj(Float f) noexcept -> enable_if_t<is_floating_point_v<Float>, complex<Float>>
{
    return complex<Float>(f);
}

template <typename Integer>
[[nodiscard]] constexpr auto conj(Integer i) noexcept -> enable_if_t<is_integral_v<Integer>, complex<double>>
{
    return complex<double>(i);
}

} // namespace etl

#endif // TETL_COMPLEX_CONJ_HPP
