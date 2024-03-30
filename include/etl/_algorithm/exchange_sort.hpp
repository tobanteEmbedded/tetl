// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_EXCHANGE_SORT_HPP
#define TETL_ALGORITHM_EXCHANGE_SORT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Sorting_algorithm#Exchange_sort
/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt, typename Compare>
constexpr auto exchange_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i < etl::prev(last); ++i) {
        for (auto j = etl::next(i); j < last; ++j) {
            if (comp(*j, *i)) {
                etl::iter_swap(i, j);
            }
        }
    }
}

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Sorting_algorithm#Exchange_sort
/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt>
constexpr auto exchange_sort(RandomIt first, RandomIt last) -> void
{
    etl::exchange_sort(first, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_EXCHANGE_SORT_HPP
