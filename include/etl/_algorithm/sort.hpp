// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_SORT_HPP
#define TETL_ALGORITHM_SORT_HPP

#include <etl/_algorithm/insertion_sort.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equal elements is not guaranteed to be preserved.
///
/// https://en.cppreference.com/w/cpp/algorithm/sort
template <typename RandomIt, typename Compare>
constexpr auto sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    etl::insertion_sort(first, last, comp);
}

template <typename RandomIt>
constexpr auto sort(RandomIt first, RandomIt last) -> void
{
    etl::sort(first, last, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_SORT_HPP
