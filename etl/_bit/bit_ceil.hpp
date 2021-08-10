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

#ifndef TETL_BIT_BIT_CEIL_HPP
#define TETL_BIT_BIT_CEIL_HPP

#include "etl/_bit/bit_unsigned_int.hpp"
#include "etl/_bit/bit_width.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/limits.hpp"

namespace etl {

/// \brief Calculates the smallest integral power of two that is not smaller
/// than x. If that value is not representable in T, the behavior is undefined.
/// Call to this function is permitted in constant evaluation only if the
/// undefined behavior does not occur.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The smallest integral power of two that is not smaller than x.
/// \module Numeric
template <typename T>
[[nodiscard]] constexpr auto bit_ceil(T x) noexcept
    -> enable_if_t<detail::bit_unsigned_int_v<T>, T>
{
    if (x <= 1U) { return T(1); }

    if constexpr (is_same_v<T, decltype(+x)>) {
        //
        return T(1) << bit_width(T(x - 1));
    } else {
        // for types subject to integral promotion
        auto offset
            = numeric_limits<unsigned>::digits - numeric_limits<T>::digits;
        return T(1U << (bit_width(T(x - 1)) + offset) >> offset);
    }
}

} // namespace etl

#endif // TETL_BIT_BIT_CEIL_HPP