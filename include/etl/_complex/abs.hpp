// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_ABS_HPP
#define TETL_COMPLEX_ABS_HPP

#include <etl/_cmath/hypot.hpp>
#include <etl/_complex/complex.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto abs(complex<T> const& z) -> T
{
    return hypot(z.real(), z.imag());
}

} // namespace etl

#endif // TETL_COMPLEX_ABS_HPP
