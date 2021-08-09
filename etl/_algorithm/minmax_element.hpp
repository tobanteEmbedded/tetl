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

#ifndef TETL_DETAIL_ALGORITHM_MINMAX_ELEMENT_HPP
#define TETL_DETAIL_ALGORITHM_MINMAX_ELEMENT_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \group minmax_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto minmax_element(
    ForwardIt first, ForwardIt last, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    auto min = first;
    auto max = first;

    if (first == last || ++first == last) { return { min, max }; }

    if (comp(*first, *min)) {
        min = first;
    } else {
        max = first;
    }

    while (++first != last) {
        auto i = first;
        if (++first == last) {
            if (comp(*i, *min)) {
                min = i;
            } else if (!(comp(*i, *max))) {
                max = i;
            }
            break;
        }

        if (comp(*first, *i)) {
            if (comp(*first, *min)) { min = first; }
            if (!(comp(*i, *max))) { max = i; }
        } else {
            if (comp(*i, *min)) { min = i; }
            if (!(comp(*first, *max))) { max = first; }
        }
    }

    return { min, max };
}

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \group minmax_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last)
    -> pair<ForwardIt, ForwardIt>
{
    using value_type = typename iterator_traits<ForwardIt>::value_type;
    return minmax_element(first, last, less<value_type>());
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_MINMAX_ELEMENT_HPP