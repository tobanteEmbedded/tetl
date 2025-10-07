// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#ifndef TETL_ALGORITHM_QUICK_SORT_HPP
#define TETL_ALGORITHM_QUICK_SORT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>

namespace etl {

namespace detail {

template <typename RandomIt, typename Compare>
constexpr auto lomuto_partition(RandomIt first, RandomIt last, Compare comp) -> RandomIt
{
    auto pivot = etl::prev(last);
    auto i     = first;

    for (auto j = first; j != pivot; ++j) {
        if (comp(*j, *pivot)) {
            etl::iter_swap(i, j);
            ++i;
        }
    }

    etl::iter_swap(i, pivot);
    return i; // final pivot position
}

} // namespace detail

/// \ingroup algorithm
/// @{

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Quick_sort
/// \note Non-standard extension
template <typename RandomIt, typename Compare>
constexpr auto quick_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    if (first == last or etl::next(first) == last) {
        return;
    }

    auto pi = etl::detail::lomuto_partition(first, last, comp);
    etl::quick_sort(first, pi, comp);
    etl::quick_sort(etl::next(pi), last, comp);
}

template <typename RandomIt>
constexpr auto quick_sort(RandomIt first, RandomIt last) -> void
{
    etl::quick_sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_QUICK_SORT_HPP
