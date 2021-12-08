/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_DISTANCE_HPP
#define TETL_ITERATOR_DISTANCE_HPP

#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_iterator/tags.hpp"
#include "etl/_type_traits/is_base_of.hpp"

namespace etl {

/// \brief Returns the number of hops from first to last.
///
/// https://en.cppreference.com/w/cpp/iterator/distance
///
/// \module Iterator
template <typename It>
constexpr auto distance(It first, It last) -> typename iterator_traits<It>::difference_type
{
    using category = typename iterator_traits<It>::iterator_category;
    static_assert(is_base_of_v<input_iterator_tag, category>);

    if constexpr (is_base_of_v<random_access_iterator_tag, category>) {
        return last - first;
    } else {
        auto result = typename iterator_traits<It>::difference_type {};
        while (first != last) {
            ++first;
            ++result;
        }
        return result;
    }
}

} // namespace etl

#endif // TETL_ITERATOR_DISTANCE_HPP