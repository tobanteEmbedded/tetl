// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_STABLE_SORT_HPP
#define TETL_ALGORITHM_STABLE_SORT_HPP

#include <etl/_algorithm/insertion_sort.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equivalent elements is guaranteed to be preserved.
/// Elements are compared using the given comparison function comp.
///
/// https://en.cppreference.com/w/cpp/algorithm/stable_sort
template <typename RandomIt, typename Compare>
constexpr auto stable_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    etl::insertion_sort(first, last, comp);
}

template <typename RandomIt>
constexpr auto stable_sort(RandomIt first, RandomIt last) -> void
{
    etl::stable_sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_STABLE_SORT_HPP
