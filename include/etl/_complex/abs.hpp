/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_ABS_HPP
#define TETL_COMPLEX_ABS_HPP

#include "etl/_cmath/hypot.hpp"
#include "etl/_complex/complex.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto abs(complex<T> const& z) -> T
{
    return hypot(z.real(), z.imag());
}

} // namespace etl

#endif // TETL_COMPLEX_ABS_HPP
