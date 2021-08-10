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

#ifndef TETL_ALGORITHM_SHIFT_LEFT_HPP
#define TETL_ALGORITHM_SHIFT_LEFT_HPP

#include "etl/_concepts/emulation.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Shifts the elements in the range [first, last) by n positions.
///
/// \details Shifts the elements towards the beginning of the range. If n == 0
/// || n >= last - first, there are no effects. If n < 0, the behavior is
/// undefined. Otherwise, for every integer i in [0, last - first - n), moves
/// the element originally at position first + n + i to position first + i. The
/// moves are performed in increasing order of i starting from ​0​.
template <typename ForwardIt>
constexpr auto shift_left(ForwardIt first, const ForwardIt last,
    typename iterator_traits<ForwardIt>::difference_type n) -> ForwardIt
{
    if (n <= 0) { return last; }
    auto start = first;
    if constexpr (detail::RandomAccessIterator<ForwardIt>) {
        if (n >= last - first) { return first; }
        start += n;
    } else {
        for (; 0 < n; --n) {
            if (start == last) { return first; }
            ++start;
        }
    }

    first = move(start, last, first);
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_SHIFT_LEFT_HPP