/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_STABLE_SORT_HPP
#define TETL_ALGORITHM_STABLE_SORT_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/next.hpp"
#include "etl/_iterator/prev.hpp"

namespace etl {

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equivalent elements is guaranteed to be preserved.
/// Elements are compared using the given comparison function comp.
///
/// \notes https://en.cppreference.com/w/cpp/algorithm/stable_sort
///
/// \group stable_sort
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto stable_sort(RandomIt first, RandomIt last, Compare cmp) -> void
{
    for (; first != last; ++first) {
        auto min = first;
        for (auto j = next(first, 1); j != last; ++j) {
            if (cmp(*j, *min)) { min = j; }
        }

        auto key = *min;
        while (min != first) {
            *min = *prev(min, 1);
            --min;
        }

        *first = key;
    }
}

/// \group stable_sort
template <typename RandomIt>
constexpr auto stable_sort(RandomIt first, RandomIt last) -> void
{
    stable_sort(first, last, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_STABLE_SORT_HPP