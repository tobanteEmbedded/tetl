// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_PARTIAL_SORT_HPP
#define TETL_ALGORITHM_PARTIAL_SORT_HPP

#include <etl/_algorithm/sort.hpp>
#include <etl/_warning/ignore_unused.hpp>

namespace etl {

/// \brief Rearranges elements such that the range `[first, middle)` contains
/// the sorted `middle - first` smallest elements in the range `[first, last)`.
/// The order of equal elements is not guaranteed to be preserved. The order of
/// the remaining elements in the range `[middle, last)` is unspecified.
///
/// https://en.cppreference.com/w/cpp/algorithm/partial_sort
template <typename RandomIt, typename Compare>
constexpr auto partial_sort(RandomIt first, RandomIt middle, RandomIt last, Compare comp) -> void
{
    // TODO: Improve. Currently forwards to regular sort.
    etl::ignore_unused(middle);
    etl::sort(first, last, comp);
}

template <typename RandomIt>
constexpr auto partial_sort(RandomIt first, RandomIt middle, RandomIt last) -> void
{
    etl::ignore_unused(middle);
    etl::sort(first, last);
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTIAL_SORT_HPP
