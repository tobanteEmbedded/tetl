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

#ifndef TETL_CMATH_COPYSIGN_HPP
#define TETL_CMATH_COPYSIGN_HPP

#include "etl/_config/builtin_functions.hpp"

namespace etl {

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(float mag, float sgn) -> float
{
    return TETL_BUILTIN_COPYSIGNF(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignf(float mag, float sgn) -> float
{
    return TETL_BUILTIN_COPYSIGNF(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(double mag, double sgn) -> double
{
    return TETL_BUILTIN_COPYSIGN(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysign(long double mag, long double sgn)
    -> long double
{
    return TETL_BUILTIN_COPYSIGNL(mag, sgn);
}

/// \brief Composes a floating point value with the magnitude of mag and the
/// sign of sgn.
///
/// \details etl::copysign is the only portable way to manipulate the sign of a
/// NaN value (to examine the sign of a NaN, signbit may also be used)
///
/// https://en.cppreference.com/w/cpp/numeric/math/copysign
///
/// \returns If no errors occur, the floating point value with the magnitude of
/// mag and the sign of sgn is returned. If mag is NaN, then NaN with the sign
/// of sgn is returned. If sgn is -0, the result is only negative if the
/// implementation supports the signed zero consistently in arithmetic
/// operations.
[[nodiscard]] constexpr auto copysignl(long double mag, long double sgn)
    -> long double
{
    return TETL_BUILTIN_COPYSIGNL(mag, sgn);
}

} // namespace etl

#endif // TETL_CMATH_COPYSIGN_HPP