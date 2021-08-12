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

#ifndef TETL_ALGORITHM_EQUAL_HPP
#define TETL_ALGORITHM_EQUAL_HPP

#include "etl/_functional/equal_to.hpp"
#include "etl/_iterator/distance.hpp"

namespace etl {

/// \brief Returns true if the range `[first1, last1)` is equal to the range
/// `[first2, first2 + (last1 - first1))`, and false otherwise.
///
/// \group equal
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, Predicate p) -> bool
{
    for (; first1 != last1; ++first1, (void)++first2) {
        if (!p(*first1, *first2)) { return false; }
    }
    return true;
}

/// \group equal
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2) -> bool
{
    return equal(first1, last1, first2, equal_to<> {});
}

/// \group equal
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, Predicate p) -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return equal(first1, last1, first2, p);
}

/// \group equal
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return equal(first1, last1, first2, last2, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_HPP