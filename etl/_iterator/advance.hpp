/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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