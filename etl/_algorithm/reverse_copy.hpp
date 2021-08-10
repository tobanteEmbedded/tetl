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

#ifndef TETL_ALGORITHM_REVERSE_COPY_HPP
#define TETL_ALGORITHM_REVERSE_COPY_HPP

namespace etl {

/// \brief Copies the elements from the range `[first, last)` to another range
/// beginning at d_first in such a way that the elements in the new range are in
/// reverse order.
/// \details If the source and destination ranges (that is, `[first, last)` and
/// [d_first, d_first+(last-first)) respectively) overlap, the behavior is
/// undefined.
///
/// \module Algorithm
template <typename BidirIt, typename OutputIt>
constexpr auto reverse_copy(BidirIt first, BidirIt last, OutputIt destination)
    -> OutputIt
{
    for (; first != last; ++destination) { *(destination) = *(--last); }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_REVERSE_COPY_HPP