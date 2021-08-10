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

#ifndef TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP
#define TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP

#include "etl/_algorithm/copy.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Computes symmetric difference of two sorted ranges: the elements that
/// are found in either of the ranges, but not in both of them are copied to the
/// range beginning at destination. The resulting range is also sorted.
///
/// \group set_symmetric_difference
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_symmetric_difference(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt destination, Compare comp)
    -> OutputIt
{
    while (first1 != last1) {
        if (first2 == last2) { return copy(first1, last1, destination); }

        if (comp(*first1, *first2)) {
            *destination++ = *first1++;
        } else {
            if (comp(*first2, *first1)) {
                *destination++ = *first2;
            } else {
                ++first1;
            }
            ++first2;
        }
    }
    return copy(first2, last2, destination);
}

/// \group set_symmetric_difference
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_symmetric_difference(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest) -> OutputIt
{
    return set_symmetric_difference(
        first1, last1, first2, last2, dest, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP