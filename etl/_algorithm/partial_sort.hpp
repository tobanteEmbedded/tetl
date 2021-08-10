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

#ifndef TETL_ALGORITHM_PARTIAL_SORT_HPP
#define TETL_ALGORITHM_PARTIAL_SORT_HPP

#include "etl/_algorithm/sort.hpp"
#include "etl/_config/warning.hpp"

namespace etl {

/// \brief Rearranges elements such that the range `[first, middle)` contains
/// the sorted `middle - first` smallest elements in the range `[first, last)`.
/// The order of equal elements is not guaranteed to be preserved. The order of
/// the remaining elements in the range `[middle, last)` is unspecified.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/partial_sort](https://en.cppreference.com/w/cpp/algorithm/partial_sort)
///
/// \group partial_sort
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto partial_sort(
    RandomIt first, RandomIt middle, RandomIt last, Compare comp) -> void
{
    // TODO: Improve. Currently forwards to regular sort.
    etl::ignore_unused(middle);
    etl::sort(first, last, comp);
}

/// \group partial_sort
template <typename RandomIt>
constexpr auto partial_sort(RandomIt first, RandomIt middle, RandomIt last)
    -> void
{
    etl::ignore_unused(middle);
    etl::sort(first, last);
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTIAL_SORT_HPP