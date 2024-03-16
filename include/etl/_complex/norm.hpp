// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_NORM_HPP
#define TETL_COMPLEX_NORM_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_type_traits/enable_if.hpp>
#include <etl/_type_traits/is_floating_point.hpp>
#include <etl/_type_traits/is_integral.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto norm(complex<T> const& z) noexcept -> T
{
    auto const x = z.real();
    auto const y = z.imag();
    return x * x + y * y;
}

template <typename Float>
[[nodiscard]] constexpr auto norm(Float f) noexcept -> enable_if_t<is_floating_point_v<Float>, complex<Float>>
{
    return etl::norm(etl::complex<Float>(f));
}

template <typename Integer>
[[nodiscard]] constexpr auto norm(Integer i) noexcept -> enable_if_t<is_integral_v<Integer>, complex<double>>
{
    return etl::norm(etl::complex<double>(i));
}

} // namespace etl

#endif // TETL_COMPLEX_NORM_HPP
