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

#ifndef TETL_CMATH_ISINF_HPP
#define TETL_CMATH_ISINF_HPP

#include "etl/_config/builtin_functions.hpp"
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
template <typename Int>
[[nodiscard]] constexpr auto isinf(Int arg)
    -> enable_if_t<is_integral_v<Int>, bool>
{
    return isinf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISINF_HPP