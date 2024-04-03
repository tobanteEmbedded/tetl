// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MERGE_SORT_HPP
#define TETL_ALGORITHM_MERGE_SORT_HPP

#include <etl/_algorithm/inplace_merge.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Merge_sort
/// \note Non-standard extension
template <typename BidirIt, typename Compare>
constexpr auto merge_sort(BidirIt first, BidirIt last, Compare comp) -> void
{
    if (last - first > 1) {
        BidirIt mid = first + (last - first) / 2;
        etl::merge_sort(first, mid, comp);
        etl::merge_sort(mid, last, comp);
        etl::inplace_merge(first, mid, last, comp);
    }
}

template <typename BidirIt>
constexpr auto merge_sort(BidirIt first, BidirIt last) -> void
{
    etl::merge_sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_MERGE_SORT_HPP
