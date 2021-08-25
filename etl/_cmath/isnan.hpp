/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ISNAN_HPP
#define TETL_CMATH_ISNAN_HPP

#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Determines if the given floating point number arg is a not-a-number
/// (NaN) value.
///
/// https://en.cppreference.com/w/cpp/numeric/math/isnan
///
/// \group isnan
/// \module Numeric
[[nodiscard]] constexpr auto isnan(float arg) -> bool { return arg != arg; }

/// \group isnan
[[nodiscard]] constexpr auto isnan(double arg) -> bool { return arg != arg; }

/// \group isnan
[[nodiscard]] constexpr auto isnan(long double arg) -> bool
{
    return arg != arg;
}

/// \brief Determines if the given floating point number arg is a not-a-number
/// (NaN) value.
/// https://en.cppreference.com/w/cpp/numeric/math/isnan
template <typename Int>
[[nodiscard]] constexpr auto isnan(Int arg)
    -> enable_if_t<is_integral_v<Int>, bool>
{
    return isnan(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISNAN_HPP