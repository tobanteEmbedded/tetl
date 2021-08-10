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

#ifndef TETL_ALGORITHM_STABLE_SORT_HPP
#define TETL_ALGORITHM_STABLE_SORT_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/next.hpp"
#include "etl/_iterator/prev.hpp"

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equivalent elements is guaranteed to be preserved.
/// Elements are compared using the given comparison function comp.
///
/// \notes https://en.cppreference.com/w/cpp/algorithm/stable_sort
///
/// \group stable_sort
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto stable_sort(RandomIt first, RandomIt last, Compare cmp) -> void
{
    for (; first != last; ++first) {
        auto min = first;
        for (auto j = next(first, 1); j != last; ++j) {
            if (cmp(*j, *min)) { min = j; }
        }

        auto key = *min;
        while (min != first) {
            *min = *prev(min, 1);
            --min;
        }

        *first = key;
    }
}

/// \group stable_sort
template <typename RandomIt>
constexpr auto stable_sort(RandomIt first, RandomIt last) -> void
{
    stable_sort(first, last, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_STABLE_SORT_HPP