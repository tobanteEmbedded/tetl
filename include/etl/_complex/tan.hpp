/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_TAN_HPP
#define TETL_COMPLEX_TAN_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/cos.hpp"
#include "etl/_complex/sin.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto tan(complex<T> const& z) -> complex<T>
{
    return sin(z) / cos(z);
}

} // namespace etl

#endif // TETL_COMPLEX_TAN_HPP
