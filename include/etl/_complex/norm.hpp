/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_NORM_HPP
#define TETL_COMPLEX_NORM_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/double_or_int.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto norm(complex<T> const& z) noexcept -> T
{
    auto const x = z.real();
    auto const y = z.imag();
    return x * x + y * y;
}

template <typename T>
    requires(detail::double_or_int<T>)
[[nodiscard]] constexpr auto norm(T z) noexcept -> double
{
    auto const c = complex<double>(z);
    return norm(c);
}

[[nodiscard]] constexpr auto norm(float z) noexcept -> float
{
    auto const c = complex<float>(z);
    return norm(c);
}

[[nodiscard]] constexpr auto norm(long double z) noexcept -> long double
{
    auto const c = complex<long double>(z);
    return norm(c);
}

} // namespace etl

#endif // TETL_COMPLEX_NORM_HPP
