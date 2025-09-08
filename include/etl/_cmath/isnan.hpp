// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CMATH_ISNAN_HPP
#define TETL_CMATH_ISNAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Determines if the given floating point number arg is a not-a-number (NaN) value.
/// \details https://en.cppreference.com/w/cpp/numeric/math/isnan
[[nodiscard]] constexpr auto isnan(float arg) -> bool
{
#if __has_builtin(__builtin_isnanf) or defined(TETL_COMPILER_GCC)
    return __builtin_isnanf(arg);
#else
    return arg != arg;
#endif
}

[[nodiscard]] constexpr auto isnan(double arg) -> bool
{
#if __has_builtin(__builtin_isnan) or defined(TETL_COMPILER_GCC)
    return __builtin_isnan(arg) != 0;
#else
    return arg != arg;
#endif
}

[[nodiscard]] constexpr auto isnan(long double arg) -> bool
{
#if __has_builtin(__builtin_isnanl) or defined(TETL_COMPILER_GCC)
    return __builtin_isnanl(arg);
#else
    return arg != arg;
#endif
}

/// Determines if the given floating point number arg is a not-a-number (NaN) value.
/// \details https://en.cppreference.com/w/cpp/numeric/math/isnan
template <integral Int>
[[nodiscard]] constexpr auto isnan(Int arg) -> bool
{
    return isnan(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ISNAN_HPP
