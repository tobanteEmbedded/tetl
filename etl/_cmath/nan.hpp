/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_NAN_HPP
#define TETL_CMATH_NAN_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Converts the implementation-defined character string arg into the
/// corresponding quiet NaN value
///
/// \details Returns the quiet NaN value that corresponds to the identifying
/// string arg or zero if the implementation does not support quiet NaNs.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nan
[[nodiscard]] constexpr auto nanf(char const* arg) noexcept -> float
{
    (void)arg;
    return TETL_BUILTIN_NANF("");
}

/// \brief Converts the implementation-defined character string arg into the
/// corresponding quiet NaN value
///
/// \details Returns the quiet NaN value that corresponds to the identifying
/// string arg or zero if the implementation does not support quiet NaNs.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nan
[[nodiscard]] constexpr auto nan(char const* arg) noexcept -> double
{
    (void)arg;
    return TETL_BUILTIN_NAN("");
}

/// \brief Converts the implementation-defined character string arg into the
/// corresponding quiet NaN value
///
/// \details Returns the quiet NaN value that corresponds to the identifying
/// string arg or zero if the implementation does not support quiet NaNs.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nan
[[nodiscard]] constexpr auto nanl(char const* arg) noexcept -> long double
{
    (void)arg;
    return TETL_BUILTIN_NANL("");
}
} // namespace etl

#endif // TETL_CMATH_NAN_HPP
