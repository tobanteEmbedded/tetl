// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ALGORITHM_GNOME_SORT_HPP
#define TETL_ALGORITHM_GNOME_SORT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/prev.hpp>

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Gnome_sort
/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt, typename Compare>
constexpr auto gnome_sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    auto i = first;
    while (i != last) {
        if (i == first or not comp(*i, *etl::prev(i))) {
            ++i;
        } else {
            etl::iter_swap(i, etl::prev(i));
            --i;
        }
    }
}

/// \brief Sorts the elements in the range `[first, last)` in non-descending order.
/// \details https://en.wikipedia.org/wiki/Gnome_sort
/// \note Non-standard extension
/// \ingroup algorithm
template <typename RandomIt>
constexpr auto gnome_sort(RandomIt first, RandomIt last) -> void
{
    etl::gnome_sort(first, last, less());
}

} // namespace etl

#endif // TETL_ALGORITHM_GNOME_SORT_HPP
