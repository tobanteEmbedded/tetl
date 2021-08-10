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

#ifndef TETL_ALGORITHM_IS_PERMUTATION_HPP
#define TETL_ALGORITHM_IS_PERMUTATION_HPP

#include "etl/_algorithm/count.hpp"
#include "etl/_algorithm/find.hpp"
#include "etl/_algorithm/mismatch.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/next.hpp"

namespace etl {

/// \brief Returns true if there exists a permutation of the elements in the
/// range `[first1, last1)` that makes that range equal to the range `[first2,
/// last2)`, where `last2` denotes `first2 + (last1 - first1)` if it was not
/// given.
///
/// \group is_permuatation
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(
    ForwardIt1 first, ForwardIt1 last, ForwardIt2 first2) -> bool
{
    // skip common prefix
    auto const [fDiff1, fDiff2] = mismatch(first, last, first2);

    // iterate over the rest, counting how many times each element
    // from `[first, last)` appears in [first2, last2)
    if (fDiff1 != last) {
        auto last2 = next(fDiff2, distance(fDiff1, last));
        for (auto i = fDiff1; i != last; ++i) {
            // this *i has been checked
            if (i != find(fDiff1, i, *i)) { continue; }

            auto m = count(fDiff2, last2, *i);
            if (m == 0 || count(i, last, *i) != m) { return false; }
        }
    }

    return true;
}

/// \group is_permuatation
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(ForwardIt1 first1, ForwardIt1 last1,
    ForwardIt2 first2, ForwardIt2 last2) -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return is_permutation(first1, last1, first2);
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_PERMUTATION_HPP