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

#ifndef TETL_CMATH_ISFINITE_HPP
#define TETL_CMATH_ISFINITE_HPP

#include "etl/_cmath/isinf.hpp"
#include "etl/_cmath/isnan.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Determines if the given floating point number arg has finite value
/// i.e. it is normal, subnormal or zero, but not infinite or NaN.
/// \notes
/// [cppreference.com/w/cpp/numeric/math/isfinite](https://en.cppreference.com/w/cpp/numeric/math/isfinite)
/// \group isfinite
/// \module Numeric
[[nodiscard]] constexpr auto isfinite(float arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/// \group isfinite
[[nodiscard]] constexpr auto isfinite(double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/// \group isfinite
[[nodiscard]] constexpr auto isfinite(long double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

} // namespace etl

#endif // TETL_CMATH_ISFINITE_HPP