// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CMATH_SIGNBIT_HPP
#define TETL_CMATH_SIGNBIT_HPP

#include "etl/_config/builtin_functions.hpp"

namespace etl {

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(float arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(double arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

/// \brief Determines if the given floating point number arg is negative.
///
/// \details This function detects the sign bit of zeroes, infinities, and NaNs.
/// Along with etl::copysign, etl::signbit is one of the only two portable ways
/// to examine the sign of a NaN.
///
/// https://en.cppreference.com/w/cpp/numeric/math/signbit
[[nodiscard]] constexpr auto signbit(long double arg) noexcept -> bool
{
    return TETL_BUILTIN_SIGNBIT(arg);
}

} // namespace etl

#endif // TETL_CMATH_SIGNBIT_HPP