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
[[nodiscard]] constexpr auto isnan(float arg) -> bool
{
#if __has_builtin(__builtin_isnanf) or defined(TETL_GCC)
    return __builtin_isnanf(arg);
#else
    return arg != arg;
#endif
}

[[nodiscard]] constexpr auto isnan(double arg) -> bool
{
#if __has_builtin(__builtin_isnan) or defined(TETL_GCC)
    return __builtin_isnan(arg);
#else
    return arg != arg;
#endif
}

[[nodiscard]] constexpr auto isnan(long double arg) -> bool
{
#if __has_builtin(__builtin_isnanl) or defined(TETL_GCC)
    return __builtin_isnanl(arg);
#else
    return arg != arg;
#endif
}

/// \brief Determines if the given floating point number arg is a not-a-number
/// (NaN) value.
/// https://en.cppreference.com/w/cpp/numeric/math/isnan
template <typename Int, enable_if_t<is_integral_v<Int>, int> = 0>
[[nodiscard]] constexpr auto isnan(Int arg) -> bool
{
    return isnan(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISNAN_HPP