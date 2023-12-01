// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_SIN_HPP
#define TETL_COMPLEX_SIN_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/sinh.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto sin(complex<T> const& z) -> complex<T>
{
    auto const x = z.real();
    auto const y = z.imag();
    return {sin(x) * cosh(y), cos(x) * sinh(y)};
}

} // namespace etl

#endif // TETL_COMPLEX_SIN_HPP
