// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_POLAR_HPP
#define TETL_COMPLEX_POLAR_HPP

#include <etl/_cmath/cos.hpp>
#include <etl/_cmath/sin.hpp>
#include <etl/_complex/complex.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto polar(T const& r, T const& theta = T()) noexcept -> etl::complex<T>
{
    return etl::complex<T>{r * etl::cos(theta), r * etl::sin(theta)};
}

} // namespace etl

#endif // TETL_COMPLEX_POLAR_HPP
