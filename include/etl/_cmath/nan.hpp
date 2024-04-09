// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_NAN_HPP
#define TETL_CMATH_NAN_HPP

#include <etl/_config/all.hpp>

namespace etl {

/// \ingroup cmath
/// @{

/// Converts the implementation-defined character string arg into the
/// corresponding quiet NaN value
///
/// Returns the quiet NaN value that corresponds to the identifying
/// string arg or zero if the implementation does not support quiet NaNs.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nan
[[nodiscard]] constexpr auto nanf(char const* arg) noexcept -> float { return TETL_BUILTIN_NANF(arg); }
[[nodiscard]] constexpr auto nan(char const* arg) noexcept -> double { return TETL_BUILTIN_NAN(arg); }
[[nodiscard]] constexpr auto nanl(char const* arg) noexcept -> long double { return TETL_BUILTIN_NANL(arg); }

/// @}

} // namespace etl

#endif // TETL_CMATH_NAN_HPP
