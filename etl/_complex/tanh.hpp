/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_TANH_HPP
#define TETL_COMPLEX_TANH_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/cosh.hpp"
#include "etl/_complex/sinh.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto tanh(complex<T> const& z) -> complex<T>
{
    return sinh(z) / cosh(z);
}

} // namespace etl

#endif // TETL_COMPLEX_TANH_HPP