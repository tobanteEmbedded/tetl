// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_ALGORITHM_IS_SORTED_UNTIL_HPP
#define TETL_ALGORITHM_IS_SORTED_UNTIL_HPP

#include "etl/_functional/less.hpp"

namespace etl {

template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first != last) {
        ForwardIt next = first;
        while (++next != last) {
            if (comp(*next, *first)) { return next; }
            first = next;
        }
    }
    return last;
}

/// \brief Examines the range `[first, last)` and finds the largest range
/// beginning at `first` in which the elements are sorted in non-descending
/// order.
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return is_sorted_until(first, last, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_SORTED_UNTIL_HPP
