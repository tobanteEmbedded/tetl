// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_ALGORITHM_HPP
#define TETL_ALGORITHM_HPP

#include "etl/version.hpp"

#include "etl/_assert/macro.hpp"

#include "etl/_algorithm/adjacent_find.hpp"
#include "etl/_algorithm/all_of.hpp"
#include "etl/_algorithm/any_of.hpp"
#include "etl/_algorithm/binary_search.hpp"
#include "etl/_algorithm/clamp.hpp"
#include "etl/_algorithm/copy.hpp"
#include "etl/_algorithm/copy_backward.hpp"
#include "etl/_algorithm/copy_if.hpp"
#include "etl/_algorithm/copy_n.hpp"
#include "etl/_algorithm/count.hpp"
#include "etl/_algorithm/count_if.hpp"
#include "etl/_algorithm/equal.hpp"
#include "etl/_algorithm/equal_range.hpp"
#include "etl/_algorithm/fill.hpp"
#include "etl/_algorithm/fill_n.hpp"
#include "etl/_algorithm/find.hpp"
#include "etl/_algorithm/find_end.hpp"
#include "etl/_algorithm/find_first_of.hpp"
#include "etl/_algorithm/find_if.hpp"
#include "etl/_algorithm/find_if_not.hpp"
#include "etl/_algorithm/for_each.hpp"
#include "etl/_algorithm/for_each_n.hpp"
#include "etl/_algorithm/generate.hpp"
#include "etl/_algorithm/generate_n.hpp"
#include "etl/_algorithm/includes.hpp"
#include "etl/_algorithm/is_partitioned.hpp"
#include "etl/_algorithm/is_permutation.hpp"
#include "etl/_algorithm/is_sorted.hpp"
#include "etl/_algorithm/is_sorted_until.hpp"
#include "etl/_algorithm/iter_swap.hpp"
#include "etl/_algorithm/lexicographical_compare.hpp"
#include "etl/_algorithm/lower_bound.hpp"
#include "etl/_algorithm/max.hpp"
#include "etl/_algorithm/max_element.hpp"
#include "etl/_algorithm/merge.hpp"
#include "etl/_algorithm/min.hpp"
#include "etl/_algorithm/min_element.hpp"
#include "etl/_algorithm/minmax.hpp"
#include "etl/_algorithm/minmax_element.hpp"
#include "etl/_algorithm/mismatch.hpp"
#include "etl/_algorithm/move.hpp"
#include "etl/_algorithm/move_backward.hpp"
#include "etl/_algorithm/none_of.hpp"
#include "etl/_algorithm/nth_element.hpp"
#include "etl/_algorithm/partial_sort.hpp"
#include "etl/_algorithm/partition.hpp"
#include "etl/_algorithm/partition_copy.hpp"
#include "etl/_algorithm/partition_point.hpp"
#include "etl/_algorithm/remove.hpp"
#include "etl/_algorithm/remove_copy.hpp"
#include "etl/_algorithm/remove_copy_if.hpp"
#include "etl/_algorithm/remove_if.hpp"
#include "etl/_algorithm/replace.hpp"
#include "etl/_algorithm/replace_if.hpp"
#include "etl/_algorithm/reverse.hpp"
#include "etl/_algorithm/reverse_copy.hpp"
#include "etl/_algorithm/rotate.hpp"
#include "etl/_algorithm/rotate_copy.hpp"
#include "etl/_algorithm/search.hpp"
#include "etl/_algorithm/search_n.hpp"
#include "etl/_algorithm/set_difference.hpp"
#include "etl/_algorithm/set_intersection.hpp"
#include "etl/_algorithm/set_symmetric_difference.hpp"
#include "etl/_algorithm/set_union.hpp"
#include "etl/_algorithm/shift_left.hpp"
#include "etl/_algorithm/sort.hpp"
#include "etl/_algorithm/stable_partition.hpp"
#include "etl/_algorithm/stable_sort.hpp"
#include "etl/_algorithm/swap.hpp"
#include "etl/_algorithm/swap_ranges.hpp"
#include "etl/_algorithm/transform.hpp"
#include "etl/_algorithm/unique.hpp"
#include "etl/_algorithm/unique_copy.hpp"
#include "etl/_algorithm/upper_bound.hpp"

#include "etl/_concepts/emulation.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_utility/pair.hpp"

// #include "etl/functional.hpp"
#include "etl/iterator.hpp"

namespace etl {

/// \brief Checks if an element equivalent to value appears within the range
/// `[first, last)`. For binary_search to succeed, the range `[first, last)`
/// must be at least partially ordered with respect to `value`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/binary_search](https://en.cppreference.com/w/cpp/algorithm/binary_search)
///
/// \group binary_search
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto binary_search(
    ForwardIt first, ForwardIt last, T const& value, Compare comp) -> bool
{
    first = lower_bound(first, last, value, comp);
    return (!(first == last) && !(comp(value, *first)));
}

/// \group binary_search
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto binary_search(
    ForwardIt first, ForwardIt last, T const& value) -> bool
{
    return binary_search(first, last, value, less<> {});
}

/// \brief Merges two sorted ranges `[first1, last1)` and `[first2, last2)` into
/// one sorted range beginning at `destination`.
///
/// \group merge
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto merge(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination, Compare comp) -> OutputIt
{
    for (; first1 != last1; ++destination) {
        if (first2 == last2) { return copy(first1, last1, destination); }
        if (comp(*first2, *first1)) {
            *destination = *first2;
            ++first2;
        } else {
            *destination = *first1;
            ++first1;
        }
    }
    return copy(first2, last2, destination);
}

/// \group merge
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto merge(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination) -> OutputIt
{
    return merge(first1, last1, first2, last2, destination, less<> {});
}

/// \brief Returns true if the sorted range `[first2, last2)` is a subsequence
/// of the sorted range `[first1, last1)`. Both ranges must be sorted.
///
/// \group includes
/// \module Algorithm
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto includes(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    for (; first2 != last2; ++first1) {
        if (first1 == last1 || *first2 < *first1) { return false; }
        if (!(*first1 < *first2)) { ++first2; }
    }
    return true;
}

/// \group includes
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, Compare comp) -> bool
{
    for (; first2 != last2; ++first1) {
        if (first1 == last1 || comp(*first2, *first1)) { return false; }
        if (!comp(*first1, *first2)) { ++first2; }
    }
    return true;
}

/// \brief Copies the elements from the sorted range `[first1, last1)` which are
/// not found in the sorted range `[first2, last2)` to the range beginning at
/// destination. Elements are compared using the given binary comparison
/// function `comp` and the ranges must be sorted with respect to the same.
///
/// \group set_difference
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_difference(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination, Compare comp) -> OutputIt
{
    while (first1 != last1) {
        if (first2 == last2) { return copy(first1, last1, destination); }

        if (comp(*first1, *first2)) {
            *destination++ = *first1++;
        } else {
            if (!comp(*first2, *first1)) { ++first1; }
            ++first2;
        }
    }
    return destination;
}

/// \group set_difference
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_difference(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination) -> OutputIt
{
    return set_difference(first1, last1, first2, last2, destination, less<> {});
}

/// \brief Constructs a sorted range beginning at `dest` consisting of elements
/// that are found in both sorted ranges `[first1, last1)` and `[first2,
/// last2)`. If some element is found `m` times in `[first1, last1)` and n times
/// in `[first2, last2)`, the first `min(m, n)` elements will be copied from the
/// first range to the destination range. The order of equivalent elements is
/// preserved. The resulting range cannot overlap with either of the input
/// ranges.
///
/// \group set_intersection
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_intersection(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest, Compare comp) -> OutputIt
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

/// \group set_intersection
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_intersection(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest) -> OutputIt
{
    return set_intersection(first1, last1, first2, last2, dest, less<>());
}

/// \brief Computes symmetric difference of two sorted ranges: the elements that
/// are found in either of the ranges, but not in both of them are copied to the
/// range beginning at destination. The resulting range is also sorted.
///
/// \group set_symmetric_difference
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_symmetric_difference(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt destination, Compare comp)
    -> OutputIt
{
    while (first1 != last1) {
        if (first2 == last2) { return copy(first1, last1, destination); }

        if (comp(*first1, *first2)) {
            *destination++ = *first1++;
        } else {
            if (comp(*first2, *first1)) {
                *destination++ = *first2;
            } else {
                ++first1;
            }
            ++first2;
        }
    }
    return copy(first2, last2, destination);
}

/// \group set_symmetric_difference
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_symmetric_difference(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, OutputIt dest) -> OutputIt
{
    return set_symmetric_difference(
        first1, last1, first2, last2, dest, less<>());
}

/// \brief Constructs a sorted union beginning at destination consisting of the
/// set of elements present in one or both sorted ranges `[first1, last1)` and
/// `[first2, last2)`. The resulting range cannot overlap with either of the
/// input ranges.
///
/// \group set_union
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename Compare>
constexpr auto set_union(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination, Compare comp) -> OutputIt
{
    for (; first1 != last1; ++destination) {
        if (first2 == last2) { return copy(first1, last1, destination); }
        if (comp(*first2, *first1)) {
            *destination = *first2++;
            continue;
        }

        *destination = *first1;
        if (!comp(*first1, *first2)) { ++first2; }
        ++first1;
    }
    return copy(first2, last2, destination);
}

/// \group set_union
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_union(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    InputIt2 last2, OutputIt destination) -> OutputIt
{
    return set_union(first1, last1, first2, last2, destination, etl::less<> {});
}

/// \brief Returns true if there exists a permutation of the elements in the
/// range `[first1, last1)` that makes that range equal to the range `[first2,
/// last2)`, where `last2` denotes `first2 + (last1 - first1)` if it was not
/// given.
///
/// \group is_permuatation
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(
    ForwardIt1 first, ForwardIt1 last, ForwardIt2 first2) -> bool
{
    // skip common prefix
    auto const [fDiff1, fDiff2] = mismatch(first, last, first2);

    // iterate over the rest, counting how many times each element
    // from `[first, last)` appears in [first2, last2)
    if (fDiff1 != last) {
        auto last2 = next(fDiff2, distance(fDiff1, last));
        for (auto i = fDiff1; i != last; ++i) {
            // this *i has been checked
            if (i != find(fDiff1, i, *i)) { continue; }

            auto m = count(fDiff2, last2, *i);
            if (m == 0 || count(i, last, *i) != m) { return false; }
        }
    }

    return true;
}

/// \group is_permuatation
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(ForwardIt1 first1, ForwardIt1 last1,
    ForwardIt2 first2, ForwardIt2 last2) -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return is_permutation(first1, last1, first2);
}

} // namespace etl

#endif // TETL_ALGORITHM_HPP