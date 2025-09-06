// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_SET_UNION_HPP
#define TETL_ALGORITHM_SET_UNION_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// \brief Constructs a sorted union beginning at destination consisting of the
/// set of elements present in one or both sorted ranges `[first1, last1)` and
/// `[first2, last2)`. The resulting range cannot overlap with either of the
/// input ranges.
template <typename InputIt1, typename InputIt2, typename OutputIt, typename Compare>
constexpr auto
set_union(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination, Compare comp)
    -> OutputIt
{
    for (; first1 != last1; ++destination) {
        if (first2 == last2) {
            return etl::copy(first1, last1, destination);
        }
        if (comp(*first2, *first1)) {
            *destination = *first2++;
            continue;
        }

        *destination = *first1;
        if (not comp(*first1, *first2)) {
            ++first2;
        }
        ++first1;
    }
    return etl::copy(first2, last2, destination);
}

template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_union(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination)
    -> OutputIt
{
    return etl::set_union(first1, last1, first2, last2, destination, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_SET_UNION_HPP
