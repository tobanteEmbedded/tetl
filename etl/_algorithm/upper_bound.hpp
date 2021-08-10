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

#ifndef TETL_ALGORITHM_UPPER_BOUND_HPP
#define TETL_ALGORITHM_UPPER_BOUND_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/advance.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/iterator_traits.hpp"

namespace etl {

/// \brief Returns an iterator pointing to the first element in the range
/// `[first, last)` that is greater than `value`, or last if no such element is
/// found.
///
/// \details The range `[first, last)` must be partitioned with respect to the
/// expression `!(value < element)` or `!comp(value, element)`, i.e., all
/// elements for which the expression is true must precede all elements for
/// which the expression is false. A fully-sorted range meets this criterion.
///
/// \group upper_bound
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto upper_bound(
    ForwardIt first, ForwardIt last, T const& value, Compare comp) -> ForwardIt
{
    using diff_t = typename iterator_traits<ForwardIt>::difference_type;

    ForwardIt it;
    diff_t count;
    diff_t step;
    count = distance(first, last);

    while (count > 0) {
        it   = first;
        step = count / 2;
        advance(it, step);
        if (!comp(value, *it)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

/// \group upper_bound
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto upper_bound(
    ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return upper_bound(first, last, value, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UPPER_BOUND_HPP