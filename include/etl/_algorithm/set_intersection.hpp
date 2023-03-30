// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SET_INTERSECTION_HPP
#define TETL_ALGORITHM_SET_INTERSECTION_HPP

#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Constructs a sorted range beginning at `dest` consisting of elements
/// that are found in both sorted ranges `[first1, last1)` and `[first2,
/// last2)`. If some element is found `m` times in `[first1, last1)` and n times
/// in `[first2, last2)`, the first `min(m, n)` elements will be copied from the
/// first range to the destination range. The order of equivalent elements is
/// preserved. The resulting range cannot overlap with either of the input
/// ranges.
template <typename InputIt1, typename InputIt2, typename OutputIt, typename Compare>
constexpr auto set_intersection(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt dest, Compare comp) -> OutputIt
{
    while (first1 != last1 && first2 != last2) {
        if (comp(*first1, *first2)) {
            ++first1;
        } else {
            if (!comp(*first2, *first1)) { *dest++ = *first1++; }
            ++first2;
        }
    }
    return dest;
}

template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_intersection(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt dest)
    -> OutputIt
{
    return set_intersection(first1, last1, first2, last2, dest, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_SET_INTERSECTION_HPP
