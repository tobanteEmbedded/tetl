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
#ifndef TETL_NUMERIC_PARTIAL_SUM_HPP
#define TETL_NUMERIC_PARTIAL_SUM_HPP

#include "etl/_functional/plus.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes the partial sums of the elements in the subranges of the
/// range [first, last) and writes them to the range beginning at destination.
/// This version uses the given binary function op, both applying etl::move to
/// their operands on the left hand side.
///
/// \details BinaryFunction must not invalidate any iterators, including the end
/// iterators, or modify any elements of the range involved.
///
/// https://en.cppreference.com/w/cpp/algorithm/partial_sum
///
/// \returns Iterator to the element past the last element written.
/// \group partial_sum
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination,
    BinaryOperation op) -> OutputIt
{
    if (first == last) { return destination; }

    auto sum     = *first;
    *destination = sum;

    while (++first != last) {
        sum            = op(etl::move(sum), *first);
        *++destination = sum;
    }

    return ++destination;
}

/// \group partial_sum
template <typename InputIt, typename OutputIt>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    return etl::partial_sum(first, last, destination, etl::plus<>());
}

} // namespace etl

#endif // TETL_NUMERIC_PARTIAL_SUM_HPP