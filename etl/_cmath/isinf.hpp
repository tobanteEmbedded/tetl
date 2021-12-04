/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ISINF_HPP
#define TETL_CMATH_ISINF_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Determines if the given floating point number arg is a positive or
/// negative infinity.
/// \returns true if arg is infinite, false otherwise
/// https://en.cppreference.com/w/cpp/numeric/math/isinf
/// \group isinf
/// \module Numeric
[[nodiscard]] constexpr auto isinf(float arg) -> bool
{
    return arg == TETL_BUILTIN_HUGE_VALF;
}

/// \group isinf
[[nodiscard]] constexpr auto isinf(double arg) -> bool
{
    return arg == TETL_BUILTIN_HUGE_VAL;
}

/// \group isinf
[[nodiscard]] constexpr auto isinf(long double arg) -> bool
{
    return arg == TETL_BUILTIN_HUGE_VALL;
}

/// \group isinf
template <typename Int, enable_if_t<is_integral_v<Int>, int> = 0>
[[nodiscard]] constexpr auto isinf(Int arg) -> bool
{
    return isinf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISINF_HPP