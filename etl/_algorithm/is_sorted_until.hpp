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
#ifndef TETL_ALGORITHM_IS_SORTED_UNTIL_HPP
#define TETL_ALGORITHM_IS_SORTED_UNTIL_HPP

#include "etl/_functional/less.hpp"

namespace etl {

/// \group is_sorted_until
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted_until(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first != last) {
        ForwardIt next = first;
        while (++next != last) {
            if (comp(*next, *first)) { return next; }
            first = next;
        }
    }
    return last;
}

/// \brief Examines the range `[first, last)` and finds the largest range
/// beginning at `first` in which the elements are sorted in non-descending
/// order.
///
/// \group is_sorted_until
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last)
    -> ForwardIt
{
    return is_sorted_until(first, last, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_SORTED_UNTIL_HPP