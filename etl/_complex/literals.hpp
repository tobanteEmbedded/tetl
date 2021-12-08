/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_LITERALS_HPP
#define TETL_COMPLEX_LITERALS_HPP

#include "etl/_complex/complex.hpp"

namespace etl {

inline namespace literals {
inline namespace complex_literals {

constexpr auto operator""_il(long double d) -> complex<long double> { return { 0.0L, static_cast<long double>(d) }; }

constexpr auto operator""_il(unsigned long long d) -> complex<long double>
{
    return { 0.0L, static_cast<long double>(d) };
}

constexpr auto operator""_i(long double d) -> complex<double> { return { 0.0, static_cast<double>(d) }; }

constexpr auto operator""_i(unsigned long long d) -> complex<double> { return { 0.0, static_cast<double>(d) }; }

constexpr auto operator""_if(long double d) -> complex<float> { return { 0.0F, static_cast<float>(d) }; }

constexpr auto operator""_if(unsigned long long d) -> complex<float> { return { 0.0F, static_cast<float>(d) }; }

} // namespace complex_literals
} // namespace literals

} // namespace etl

#endif // TETL_COMPLEX_LITERALS_HPP