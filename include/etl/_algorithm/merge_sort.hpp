// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

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
template <typename RandomIt, typename Compare>
constexpr auto merge_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    if (last - first > 1) {
        RandomIt mid = first + (last - first) / 2;
        etl::merge_sort(first, mid, comp);
        etl::merge_sort(mid, last, comp);
        etl::inplace_merge(first, mid, last, comp);
    }
}

template <typename RandomIt>
constexpr auto merge_sort(RandomIt first, RandomIt last) -> void
{
    etl::merge_sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_MERGE_SORT_HPP
