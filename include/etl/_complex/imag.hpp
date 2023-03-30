// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_IMAG_HPP
#define TETL_COMPLEX_IMAG_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/double_or_int.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto imag(complex<T> const& z) -> T
{
    return z.imag();
}

template <typename T>
    requires(detail::double_or_int<T>)
[[nodiscard]] constexpr auto imag(T z) -> double
{
    return static_cast<double>(z);
}

[[nodiscard]] constexpr auto imag(float z) -> float { return z; }
[[nodiscard]] constexpr auto imag(long double z) -> long double { return z; }

} // namespace etl

#endif // TETL_COMPLEX_IMAG_HPP
