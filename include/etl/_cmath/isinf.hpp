/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ISINF_HPP
#define TETL_CMATH_ISINF_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Determines if the given floating point number arg is a positive or
/// negative infinity.
/// \returns true if arg is infinite, false otherwise
/// https://en.cppreference.com/w/cpp/numeric/math/isinf
[[nodiscard]] constexpr auto isinf(float arg) -> bool
{
    if (!is_constant_evaluated()) {
#if __has_builtin(__builtin_isinf)
        return __builtin_isinf(arg) != 0;
#endif
    }
    return arg == TETL_BUILTIN_HUGE_VALF;
}

[[nodiscard]] constexpr auto isinf(double arg) -> bool
{
    if (!is_constant_evaluated()) {
#if __has_builtin(__builtin_isinf)
        return __builtin_isinf(arg) != 0;
#endif
    }
    return arg == TETL_BUILTIN_HUGE_VAL;
}

[[nodiscard]] constexpr auto isinf(long double arg) -> bool
{
    if (!is_constant_evaluated()) {
#if __has_builtin(__builtin_isinf)
        return __builtin_isinf(arg) != 0;
#endif
    }
    return arg == TETL_BUILTIN_HUGE_VALL;
}

template <integral Int>
[[nodiscard]] constexpr auto isinf(Int arg) -> bool
{
    if (!is_constant_evaluated()) {
#if __has_builtin(__builtin_isinf)
        return __builtin_isinf(static_cast<double>(arg)) != 0;
#endif
    }
    return isinf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISINF_HPP
