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
#ifndef TETL_NUMERIC_MIDPOINT_HPP
#define TETL_NUMERIC_MIDPOINT_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_numeric/abs.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_pointer.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/make_unsigned.hpp"

namespace etl {

/// \brief Returns half the sum of a + b. If the sum is odd, the result is
/// rounded towards a.
///
/// \details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?”
///
/// \notes
/// [.youtube.com/watch?v=sBtAGxBh-XI](https://www.youtube.com/watch?v=sBtAGxBh-XI)
///
/// \notes
/// [cppreference.com/w/cpp/numeric/midpoint](https://en.cppreference.com/w/cpp/numeric/midpoint)
/// \group midpoint
template <typename Int,
    TETL_REQUIRES_((is_integral_v<Int> && !is_same_v<Int, bool>))>
constexpr auto midpoint(Int a, Int b) noexcept -> Int
{
    using U = make_unsigned_t<Int>;

    auto sign = 1;
    auto m    = static_cast<U>(a);
    auto n    = static_cast<U>(b);

    if (a > b) {
        sign = -1;
        m    = static_cast<U>(b);
        n    = static_cast<U>(a);
    }

    return static_cast<Int>(
        a + static_cast<Int>(sign * static_cast<Int>(U(n - m) >> 1)));
}

/// \group midpoint
template <typename Float, TETL_REQUIRES_(is_floating_point_v<Float>)>
constexpr auto midpoint(Float a, Float b) noexcept -> Float
{
    auto const lo = numeric_limits<Float>::min() * 2;
    auto const hi = numeric_limits<Float>::max() / 2;

    if (etl::abs(a) <= hi && etl::abs(b) <= hi) { return (a + b) / 2; }
    if (etl::abs(a) < lo) { return a + b / 2; }
    if (etl::abs(b) < lo) { return a / 2 + b; }

    return a / 2 + b / 2;
}

/// \group midpoint
/// \synopsis_return Pointer
template <typename Pointer>
constexpr auto midpoint(Pointer a, Pointer b) noexcept
    -> enable_if_t<is_pointer_v<Pointer>, Pointer>
{
    return a + midpoint(ptrdiff_t { 0 }, b - a);
}

} // namespace etl

#endif // TETL_NUMERIC_MIDPOINT_HPP