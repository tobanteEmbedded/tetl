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

#ifndef TETL_ALGORITHM_UNIQUE_HPP
#define TETL_ALGORITHM_UNIQUE_HPP

#include "etl/_functional/equal_to.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
constexpr auto unique(ForwardIt first, ForwardIt last, Predicate pred)
    -> ForwardIt
{
    if (first == last) { return last; }

    auto result = first;
    while (++first != last) {
        if (!pred(*result, *first) && ++result != first) {
            *result = move(*first);
        }
    }
    return ++result;
}

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt>
constexpr auto unique(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return unique(first, last, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_HPP