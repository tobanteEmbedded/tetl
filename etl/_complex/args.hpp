/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_ARGS_HPP
#define TETL_COMPLEX_ARGS_HPP

#include "etl/_cmath/atan2.hpp"
#include "etl/_complex/complex.hpp"
#include "etl/_complex/double_or_int.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto arg(complex<T> const& z) noexcept -> T
{
    return atan2(z.real(), z.imag());
}

template <typename T, enable_if_t<detail::double_or_int<T>, int> = 0>
[[nodiscard]] constexpr auto arg(T z) noexcept -> double
{
    auto const c = complex<double>(z);
    return arg(c);
}

[[nodiscard]] constexpr auto arg(float z) noexcept -> float
{
    auto const c = complex<float>(z);
    return arg(c);
}

[[nodiscard]] constexpr auto arg(long double z) noexcept -> long double
{
    auto const c = complex<long double>(z);
    return arg(c);
}

} // namespace etl

#endif // TETL_COMPLEX_ARGS_HPP