// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_EXCHANGE_SORT_HPP
#define TETL_ALGORITHM_EXCHANGE_SORT_HPP

#include "etl/_algorithm/iter_swap.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_iterator/next.hpp"
#include "etl/_iterator/prev.hpp"

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order.
/// https://en.wikipedia.org/wiki/Sorting_algorithm#Exchange_sort
template <typename RandomIt, typename Compare>
constexpr auto exchange_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i < prev(last); ++i) {
        for (auto j = next(i); j < last; ++j) {
            if (comp(*j, *i)) { iter_swap(i, j); }
        }
    }
}

template <typename RandomIt>
constexpr auto exchange_sort(RandomIt first, RandomIt last) -> void
{
    exchange_sort(first, last, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_EXCHANGE_SORT_HPP
