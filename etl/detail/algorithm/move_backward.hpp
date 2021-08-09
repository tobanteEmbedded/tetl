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

#ifndef TETL_DETAIL_ALGORITHM_MOVE_BACKWARD_HPP
#define TETL_DETAIL_ALGORITHM_MOVE_BACKWARD_HPP

#include "etl/detail/utility/move.hpp"

namespace etl {

/// \brief Moves the elements from the range `[first, last)`, to another range
/// ending at destination. The elements are moved in reverse order (the last
/// element is moved first), but their relative order is preserved.
///
/// \param first The range of elements to move.
/// \param last The range of elements to move.
/// \param destination End of the destination range.
///
/// \returns Iterator in the destination range, pointing at the last element
/// moved.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/move_backward](https://en.cppreference.com/w/cpp/algorithm/move_backward)
///
/// \module Algorithm
template <typename BidirIt1, typename BidirIt2>
constexpr auto move_backward(
    BidirIt1 first, BidirIt1 last, BidirIt2 destination) -> BidirIt2
{
    for (; first != last;) { *(--destination) = move(*--last); }
    return destination;
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_MOVE_BACKWARD_HPP