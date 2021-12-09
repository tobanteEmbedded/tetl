/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_COSH_HPP
#define TETL_COMPLEX_COSH_HPP

#include "etl/_cmath/cos.hpp"
#include "etl/_cmath/cosh.hpp"
#include "etl/_cmath/sin.hpp"
#include "etl/_cmath/sinh.hpp"
#include "etl/_complex/complex.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto cosh(complex<T> const& z) -> complex<T>
{
    auto const x = z.real();
    auto const y = z.imag();
    return { cosh(x) * cos(y), sinh(x) * sin(y) };
}

} // namespace etl

#endif // TETL_COMPLEX_COSH_HPP