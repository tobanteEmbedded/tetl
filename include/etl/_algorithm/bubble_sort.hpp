// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_BUBBLE_SORT_HPP
#define TETL_ALGORITHM_BUBBLE_SORT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equal elements is guaranteed to be preserved.
///
/// https://en.wikipedia.org/wiki/Bubble_sort
///
/// \note Non-standard extension
template <typename RandomIt, typename Compare>
constexpr auto bubble_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i != last; ++i) {
        for (auto j = first; j < i; ++j) {
            if (comp(*i, *j)) {
                etl::iter_swap(i, j);
            }
        }
    }
}

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equal elements is guaranteed to be preserved.
///
/// https://en.wikipedia.org/wiki/Bubble_sort
///
/// \note Non-standard extension
template <typename RandomIt>
constexpr auto bubble_sort(RandomIt first, RandomIt last) -> void
{
    etl::bubble_sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_BUBBLE_SORT_HPP
