// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_IMAG_HPP
#define TETL_COMPLEX_IMAG_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_type_traits/enable_if.hpp>
#include <etl/_type_traits/is_floating_point.hpp>
#include <etl/_type_traits/is_integral.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto imag(complex<T> const& z) -> T
{
    return z.imag();
}

template <typename Float>
[[nodiscard]] constexpr auto imag(Float /*f*/) noexcept -> enable_if_t<is_floating_point_v<Float>, Float>
{
    return Float{};
}

template <typename Integer>
[[nodiscard]] constexpr auto imag(Integer /*i*/) noexcept -> enable_if_t<is_integral_v<Integer>, double>
{
    return 0.0;
}

} // namespace etl

#endif // TETL_COMPLEX_IMAG_HPP
