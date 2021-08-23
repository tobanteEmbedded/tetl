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
#ifndef TETL_NUMERIC_ACCUMULATE_HPP
#define TETL_NUMERIC_ACCUMULATE_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes the sum of the given value init and the elements in the
/// range `[first, last)`.
/// https://en.cppreference.com/w/cpp/algorithm/accumulate
/// \group accumulate
/// \module Algorithm
template <typename InputIt, typename Type>
[[nodiscard]] constexpr auto accumulate(
    InputIt first, InputIt last, Type init) noexcept -> Type
{
    for (; first != last; ++first) { init = move(init) + *first; }
    return init;
}

/// \group accumulate
template <typename InputIt, typename Type, typename BinaryOperation>
[[nodiscard]] constexpr auto accumulate(
    InputIt first, InputIt last, Type init, BinaryOperation op) noexcept -> Type
{
    for (; first != last; ++first) { init = op(move(init), *first); }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_ACCUMULATE_HPP