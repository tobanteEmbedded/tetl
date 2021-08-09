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

#ifndef TETL_DETAIL_ALGORITHM_MISMATCH_HPP
#define TETL_DETAIL_ALGORITHM_MISMATCH_HPP

#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Returns the first mismatching pair of elements from two ranges: one
/// defined by `[first1, last1)` and another defined by [first2,last2). If last2
/// is not provided (overloads (1-4)), it denotes first2 + (last1 - first1).
/// Elements are compared using the given binary predicate pred.
///
/// \param first1 The first range of the elements.
/// \param last1 The first range of the elements.
/// \param first2 The second range of the elements.
/// \param pred Binary predicate which returns ​true if the elements should be
/// treated as equal.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/mismatch](https://en.cppreference.com/w/cpp/algorithm/mismatch)
///
/// \group mismatch
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto mismatch(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, Predicate pred) -> pair<InputIt1, InputIt2>
{
    for (; first1 != last1; ++first1, ++first2) {
        if (!pred(*first1, *first2)) { break; }
    }

    return pair<InputIt1, InputIt2>(first1, first2);
}

/// \group mismatch
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto mismatch(InputIt1 first1, InputIt1 last1,
    InputIt2 first2) -> pair<InputIt1, InputIt2>
{
    return mismatch(first1, last1, first2, equal_to<> {});
}

/// \group mismatch
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto mismatch(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, Predicate pred) -> pair<InputIt1, InputIt2>
{
    for (; first1 != last1 && first2 != last2; ++first1, ++first2) {
        if (!pred(*first1, *first2)) { break; }
    }

    return pair<InputIt1, InputIt2>(first1, first2);
}

/// \group mismatch
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto mismatch(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2) -> pair<InputIt1, InputIt2>
{
    return mismatch(first1, last1, first2, last2, equal_to<> {});
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_MISMATCH_HPP