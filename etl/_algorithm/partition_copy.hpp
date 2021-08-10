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

#ifndef TETL_ALGORITHM_PARTITION_COPY_HPP
#define TETL_ALGORITHM_PARTITION_COPY_HPP

#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Copies the elements from the range `[first, last)` to two different
/// ranges depending on the value returned by the predicate p. The elements that
/// satisfy the predicate p are copied to the range beginning at
/// destination_true. The rest of the elements are copied to the range beginning
/// at destination_false.
/// \details The behavior is undefined if the input range overlaps either of the
/// output ranges.
///
/// \module Algorithm
template <typename InputIt, typename OutputIt1, typename OutputIt2,
    typename Predicate>
constexpr auto partition_copy(InputIt first, InputIt last,
    OutputIt1 destinationTrue, OutputIt2 destinationFalse, Predicate p)
    -> pair<OutputIt1, OutputIt2>
{
    for (; first != last; ++first) {
        if (p(*first)) {
            *destinationTrue = *first;
            ++destinationTrue;
        } else {
            *destinationFalse = *first;
            ++destinationFalse;
        }
    }

    return make_pair(destinationTrue, destinationFalse);
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTITION_COPY_HPP