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
#ifndef TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP
#define TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP

#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes the differences between the second and the first of each
/// adjacent pair of elements of the range [first, last) and writes them to the
/// range beginning at destination + 1. An unmodified copy of *first is written
/// to *destination.
/// \group adjacent_difference
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto adjacent_difference(InputIt first, InputIt last,
    OutputIt destination, BinaryOperation op) -> OutputIt
{
    using value_t = typename etl::iterator_traits<InputIt>::value_type;

    if (first == last) { return destination; }

    value_t acc  = *first;
    *destination = acc;

    while (++first != last) {
        value_t val    = *first;
        *++destination = op(val, move(acc));
        acc            = move(val);
    }

    return ++destination;
}

/// \group adjacent_difference
template <typename InputIt, typename OutputIt>
constexpr auto adjacent_difference(
    InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    using value_t = typename etl::iterator_traits<InputIt>::value_type;

    if (first == last) { return destination; }

    value_t acc  = *first;
    *destination = acc;

    while (++first != last) {
        value_t val    = *first;
        *++destination = val - move(acc);
        acc            = move(val);
    }

    return ++destination;
}

} // namespace etl

#endif // TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP