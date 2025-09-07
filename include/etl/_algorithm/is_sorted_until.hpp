// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch
#ifndef TETL_ALGORITHM_IS_SORTED_UNTIL_HPP
#define TETL_ALGORITHM_IS_SORTED_UNTIL_HPP

#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first != last) {
        ForwardIt next = first;
        while (++next != last) {
            if (comp(*next, *first)) {
                return next;
            }
            first = next;
        }
    }
    return last;
}

/// \brief Examines the range `[first, last)` and finds the largest range
/// beginning at `first` in which the elements are sorted in non-descending
/// order.
/// \ingroup algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return etl::is_sorted_until(first, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_SORTED_UNTIL_HPP
