// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_LITERALS_HPP
#define TETL_COMPLEX_LITERALS_HPP

#include "etl/_complex/complex.hpp"

namespace etl::inline literals::inline complex_literals {

constexpr auto operator""_il(long double d) -> complex<long double> { return {0.0L, static_cast<long double>(d)}; }

constexpr auto operator""_il(unsigned long long d) -> complex<long double>
{
    return {0.0L, static_cast<long double>(d)};
}

constexpr auto operator""_i(long double d) -> complex<double> { return {0.0, static_cast<double>(d)}; }

constexpr auto operator""_i(unsigned long long d) -> complex<double> { return {0.0, static_cast<double>(d)}; }

constexpr auto operator""_if(long double d) -> complex<float> { return {0.0F, static_cast<float>(d)}; }

constexpr auto operator""_if(unsigned long long d) -> complex<float> { return {0.0F, static_cast<float>(d)}; }

} // namespace etl::inline literals::inline complex_literals

#endif // TETL_COMPLEX_LITERALS_HPP
