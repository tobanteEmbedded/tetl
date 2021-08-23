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

#ifndef TETL_ITERATOR_ADVANCE_HPP
#define TETL_ITERATOR_ADVANCE_HPP

#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_iterator/tags.hpp"
#include "etl/_type_traits/is_base_of.hpp"

namespace etl {

/// \brief Increments given iterator it by n elements. If n is negative, the
/// iterator is decremented. In this case, InputIt must meet the requirements of
/// LegacyBidirectionalIterator, otherwise the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/iterator/advance
///
/// \module Iterator
template <typename It, typename Distance>
constexpr auto advance(It& it, Distance n) -> void
{
    using category = typename iterator_traits<It>::iterator_category;
    static_assert(is_base_of_v<input_iterator_tag, category>);

    auto dist = typename iterator_traits<It>::difference_type(n);
    if constexpr (is_base_of_v<random_access_iterator_tag, category>) {
        it += dist;
    } else {
        while (dist > 0) {
            --dist;
            ++it;
        }
        if constexpr (is_base_of_v<bidirectional_iterator_tag, category>) {
            while (dist < 0) {
                ++dist;
                --it;
            }
        }
    }
}

} // namespace etl

#endif // TETL_ITERATOR_ADVANCE_HPP