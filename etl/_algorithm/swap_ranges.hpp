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

#ifndef TETL_ALGORITHM_SWAP_RANGES_HPP
#define TETL_ALGORITHM_SWAP_RANGES_HPP

#include "etl/_algorithm/iter_swap.hpp"

namespace etl {

/// \brief Exchanges elements between range `[first1 ,last1)` and another range
/// starting at `first2`.
///
/// \param first1 The first range of elements to swap.
/// \param last1 The first range of elements to swap.
/// \param first2 Beginning of the second range of elements to swap.
///
/// \returns Iterator to the element past the last element exchanged in the
/// range beginning with `first2`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/swap_ranges](https://en.cppreference.com/w/cpp/algorithm/swap_ranges)
///
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2>
constexpr auto swap_ranges(
    ForwardIt1 first1, ForwardIt1 last1, ForwardIt2 first2) -> ForwardIt2
{
    while (first1 != last1) {
        iter_swap(first1, first2);
        ++first1;
        ++first2;
    }

    return first2;
}

} // namespace etl

#endif // TETL_ALGORITHM_SWAP_RANGES_HPP