// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_NTH_ELEMENT_HPP
#define TETL_ALGORITHM_NTH_ELEMENT_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_algorithm/sort.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>

namespace etl {

namespace detail {

template <typename Iter, typename Compare>
constexpr auto median_of_three(Iter a, Iter b, Iter c, Compare comp) -> Iter
{
    if (comp(*a, *b)) {
        if (comp(*b, *c)) {
            return b; // a < b < c
        }
        if (comp(*a, *c)) {
            return c; // a < c <= b
        }
        return a; // c <= a < b
    }

    // !(a < b)
    if (comp(*a, *c)) {
        return a; // b <= a < c
    }
    if (comp(*b, *c)) {
        return c; // b < c <= a
    }
    return b; // c <= b <= a
}

template <typename RandomIt, typename Compare>
constexpr auto unguarded_partition(RandomIt first, RandomIt last, RandomIt pivot, Compare comp) -> RandomIt
{
    while (true) {
        while (comp(*first, *pivot)) {
            ++first;
        }
        --last;
        while (comp(*pivot, *last)) {
            --last;
        }
        if (not(first < last)) {
            return first;
        }
        etl::iter_swap(first, last);
        ++first;
    }
}

} // namespace detail

/// \brief nth_element is a partial sorting algorithm that rearranges elements
/// in `[first, last)` such that:
/// - The element pointed at by nth is changed to whatever element would occur
/// in that position if `[first, last)` were sorted.
/// - All of the elements before this new nth element are less than or equal to
/// the elements after the new nth element.
///
/// https://en.cppreference.com/w/cpp/algorithm/nth_element
///
/// \ingroup algorithm
template <typename RandomIt, typename Compare>
constexpr auto nth_element(RandomIt first, RandomIt nth, RandomIt last, Compare comp) -> void
{
    constexpr auto threshold = 16;

    while (last - first > threshold) {
        auto const middle = etl::next(first, (last - first) / 2);
        auto const pivot  = etl::detail::median_of_three(first, middle, etl::prev(last), comp);
        auto const cut    = etl::detail::unguarded_partition(first, last, pivot, comp);

        if (nth < cut) {
            last = cut; // recurse left
        } else {
            first = cut; // recurse right
        }
    }

    etl::sort(first, last, comp);
}

template <typename RandomIt>
constexpr auto nth_element(RandomIt first, RandomIt nth, RandomIt last) -> void
{
    etl::nth_element(first, nth, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_NTH_ELEMENT_HPP
