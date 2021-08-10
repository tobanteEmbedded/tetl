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

#ifndef TETL_ALGORITHM_SET_INTERSECTION_HPP
#define TETL_ALGORITHM_SET_INTERSECTION_HPP

#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Constructs a sorted range beginning at `dest` consisting of elements
/// that are found in both sorted ranges `[first1, last1)` and `[first2,
/// last2)`. If some element is found `m` times in `[first1, last1)` and n times
/// in `[first2, last2)`, the first `min(m, n)` elements will be copied from the
/// first range to the destination range. The order of equivalent elements is
/// preserved. The resulting range cannot overlap with either of the input
/// ranges.
///
/// \group set_intersection
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_intersection(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest, Compare comp) -> OutputIt
{
    while (first1 != last1 && first2 != last2) {
        if (comp(*first1, *first2)) {
            ++first1;
        } else {
            if (!comp(*first2, *first1)) { *dest++ = *first1++; }
            ++first2;
        }
    }
    return dest;
}

/// \group set_intersection
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_intersection(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest) -> OutputIt
{
    return set_intersection(first1, last1, first2, last2, dest, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_SET_INTERSECTION_HPP