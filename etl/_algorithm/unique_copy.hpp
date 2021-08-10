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

#ifndef TETL_ALGORITHM_UNIQUE_COPY_HPP
#define TETL_ALGORITHM_UNIQUE_COPY_HPP

#include "etl/_functional/equal_to.hpp"

namespace etl {

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using the given binary predicate pred. The
/// behavior is undefined if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination,
    Predicate pred) -> OutputIt
{
    if (first != last) {
        *destination = *first;

        while (++first != last) {
            if (!pred(*destination, *first)) { *++destination = *first; }
        }

        ++destination;
    }

    return destination;
}

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using operator==. The behavior is undefined
/// if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    return unique_copy(first, last, destination, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_COPY_HPP