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

#ifndef TETL_DETAIL_ALGORITHM_ITER_SWAP_HPP
#define TETL_DETAIL_ALGORITHM_ITER_SWAP_HPP

#include "etl/_algorithm/swap.hpp"

namespace etl {

/// \brief Swaps the values of the elements the given iterators are pointing to.
///
/// \param a Iterators to the elements to swap.
/// \param b Iterators to the elements to swap.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/iter_swap](https://en.cppreference.com/w/cpp/algorithm/iter_swap)
///
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2>
constexpr auto iter_swap(ForwardIt1 a, ForwardIt2 b) -> void
{
    using etl::swap;
    swap(*a, *b);
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_ITER_SWAP_HPP