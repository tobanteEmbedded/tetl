// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ALGORITHM_INSERTION_SORT_HPP
#define TETL_ALGORITHM_INSERTION_SORT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equal elements is guaranteed to be preserved.
///
/// https://en.wikipedia.org/wiki/Insertion_sort
///
/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt, typename Compare>
constexpr auto insertion_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i != last; ++i) {
        auto key = *i;
        auto j   = i;
        while (j != first and comp(key, *(j - 1))) {
            *j = *(j - 1);
            --j;
        }
        *j = key;
    }
}

/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt>
constexpr auto insertion_sort(RandomIt first, RandomIt last) -> void
{
    etl::insertion_sort(first, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_INSERTION_SORT_HPP
