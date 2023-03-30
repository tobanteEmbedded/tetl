// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_GNOME_SORT_HPP
#define TETL_ALGORITHM_GNOME_SORT_HPP

#include "etl/_algorithm/iter_swap.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_iterator/prev.hpp"

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order.
/// https://en.wikipedia.org/wiki/Gnome_sort
template <typename BidirIt, typename Compare>
constexpr auto gnome_sort(BidirIt first, BidirIt last, Compare comp) -> void
{
    auto i = first;
    while (i != last) {
        if (i == first or not comp(*i, *prev(i))) {
            ++i;
        } else {
            iter_swap(i, prev(i));
            --i;
        }
    }
}

template <typename BidirIt>
constexpr auto gnome_sort(BidirIt first, BidirIt last) -> void
{
    gnome_sort(first, last, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_GNOME_SORT_HPP
