/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MERGE_SORT_HPP
#define TETL_ALGORITHM_MERGE_SORT_HPP

#include "etl/_algorithm/inplace_merge.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order.
/// https://en.wikipedia.org/wiki/Merge_sort
template <typename BidirIt, typename Compare>
constexpr auto merge_sort(BidirIt first, BidirIt last, Compare comp) -> void
{
    if (last - first > 1) {
        BidirIt mid = first + (last - first) / 2;
        merge_sort(first, mid, comp);
        merge_sort(mid, last, comp);
        inplace_merge(first, mid, last, comp);
    }
}

template <typename BidirIt>
constexpr auto merge_sort(BidirIt first, BidirIt last) -> void
{
    merge_sort(first, last, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_MERGE_SORT_HPP
