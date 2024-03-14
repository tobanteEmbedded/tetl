// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_TAN_HPP
#define TETL_COMPLEX_TAN_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_complex/cos.hpp>
#include <etl/_complex/sin.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto tan(complex<T> const& z) -> complex<T>
{
    return sin(z) / cos(z);
}

} // namespace etl

#endif // TETL_COMPLEX_TAN_HPP
