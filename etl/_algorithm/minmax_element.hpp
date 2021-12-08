/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MINMAX_ELEMENT_HPP
#define TETL_ALGORITHM_MINMAX_ELEMENT_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \group minmax_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last, Compare comp) -> pair<ForwardIt, ForwardIt>
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
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last) -> pair<ForwardIt, ForwardIt>
{
    using value_type = typename iterator_traits<ForwardIt>::value_type;
    return minmax_element(first, last, less<value_type>());
}

} // namespace etl

#endif // TETL_ALGORITHM_MINMAX_ELEMENT_HPP