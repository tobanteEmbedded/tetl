/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
    return { sin(x) * cosh(y), cos(x) * sinh(y) };
}

} // namespace etl

#endif // TETL_COMPLEX_SIN_HPP