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

#ifndef TETL_BIT_TOGGLE_BIT_HPP
#define TETL_BIT_TOGGLE_BIT_HPP

#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_unsigned.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto toggle_bit(T val, T bit) noexcept
    -> enable_if_t<is_unsigned_v<T>, T>
{
    return val ^= T(1) << bit;
}

} // namespace etl

static_assert(etl::toggle_bit(0b00000001U, 0U) == 0b00000000U);
static_assert(etl::toggle_bit(0b00000010U, 1U) == 0b00000000U);
static_assert(etl::toggle_bit(0b00000100U, 2U) == 0b00000000U);
static_assert(etl::toggle_bit(0b00000011U, 3U) == 0b00001011U);

#endif // TETL_BIT_TOGGLE_BIT_HPP