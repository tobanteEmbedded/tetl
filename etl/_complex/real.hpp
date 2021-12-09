/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_REAL_HPP
#define TETL_COMPLEX_REAL_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/double_or_int.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto real(complex<T> const& z) -> T
{
    return z.real();
}

template <typename T, enable_if_t<detail::double_or_int<T>, int> = 0>
[[nodiscard]] constexpr auto real(T z) -> double
{
    return static_cast<double>(z);
}

[[nodiscard]] constexpr auto real(float z) -> float { return z; }

[[nodiscard]] constexpr auto real(long double z) -> long double { return z; }

} // namespace etl

#endif // TETL_COMPLEX_REAL_HPP