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

#ifndef TETL_CMATH_LERP_HPP
#define TETL_CMATH_LERP_HPP

#include "etl/_math/lerp.hpp"

namespace etl {

/// \brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
/// the parameter t (or extrapolation, when t is outside the range [0,1]).
///
/// https://en.cppreference.com/w/cpp/numeric/lerp
/// \group lerp
/// \module Numeric
[[nodiscard]] constexpr auto lerp(float a, float b, float t) noexcept -> float
{
    return detail::lerp_impl<float>(a, b, t);
}

/// \group lerp
[[nodiscard]] constexpr auto lerp(double a, double b, double t) noexcept
    -> double
{
    return detail::lerp_impl<double>(a, b, t);
}

/// \group lerp
[[nodiscard]] constexpr auto lerp(
    long double a, long double b, long double t) noexcept -> long double
{
    return detail::lerp_impl<long double>(a, b, t);
}
} // namespace etl

#endif // TETL_CMATH_LERP_HPP