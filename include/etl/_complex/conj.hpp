// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_CONJ_HPP
#define TETL_COMPLEX_CONJ_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_concepts/floating_point.hpp"
#include "etl/_concepts/integral.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto conj(complex<T> const& z) noexcept -> complex<T>
{
    return complex<T>(z.real(), -z.imag());
}

template <floating_point Float>
[[nodiscard]] constexpr auto conj(Float f) noexcept -> complex<Float>
{
    return complex<Float>(f);
}

template <integral Integer>
[[nodiscard]] constexpr auto conj(Integer i) noexcept -> complex<double>
{
    return complex<double>(i);
}

} // namespace etl

#endif // TETL_COMPLEX_CONJ_HPP
