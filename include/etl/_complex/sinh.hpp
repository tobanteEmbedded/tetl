// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_SINH_HPP
#define TETL_COMPLEX_SINH_HPP

#include "etl/_cmath/cos.hpp"
#include "etl/_cmath/cosh.hpp"
#include "etl/_cmath/sin.hpp"
#include "etl/_cmath/sinh.hpp"
#include "etl/_complex/complex.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto sinh(complex<T> const& z) -> complex<T>
{
    auto const x = z.real();
    auto const y = z.imag();
    return { sinh(x) * cos(y), cosh(x) * sin(y) };
}

} // namespace etl

#endif // TETL_COMPLEX_SINH_HPP
