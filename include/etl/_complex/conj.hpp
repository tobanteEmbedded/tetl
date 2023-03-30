/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_CONJ_HPP
#define TETL_COMPLEX_CONJ_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/double_or_int.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto conj(complex<T> const& z) noexcept -> complex<T>
{
    return complex<T>(z.real(), -z.imag());
}

template <typename T>
    requires(detail::double_or_int<T>)
[[nodiscard]] constexpr auto conj(T z) noexcept -> complex<double>
{
    auto const c = complex<double>(z);
    return conj(c);
}

[[nodiscard]] constexpr auto conj(float z) noexcept -> complex<float>
{
    auto const c = complex<float>(z);
    return conj(c);
}

[[nodiscard]] constexpr auto conj(long double z) noexcept -> complex<long double>
{
    auto const c = complex<long double>(z);
    return conj(c);
}

} // namespace etl

#endif // TETL_COMPLEX_CONJ_HPP
