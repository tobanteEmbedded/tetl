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
#include "etl/_algorithm/count.hpp"
#include "etl/_algorithm/count_if.hpp"
#include "etl/_algorithm/find.hpp"
#include "etl/_algorithm/find_end.hpp"
#include "etl/_algorithm/find_first_of.hpp"
#include "etl/_algorithm/find_if.hpp"
#include "etl/_algorithm/find_if_not.hpp"
#include "etl/_algorithm/for_each.hpp"
#include "etl/_algorithm/for_each_n.hpp"
#include "etl/_algorithm/generate.hpp"
#include "etl/_algorithm/generate_n.hpp"
#include "etl/_algorithm/iter_swap.hpp"
#include "etl/_algorithm/mismatch.hpp"
#include "etl/_algorithm/move.hpp"
#include "etl/_algorithm/move_backward.hpp"
#include "etl/_algorithm/remove.hpp"
#include "etl/_algorithm/remove_copy.hpp"
#include "etl/_algorithm/remove_copy_if.hpp"
#include "etl/_algorithm/remove_if.hpp"
#include "etl/_algorithm/replace.hpp"
#include "etl/_algorithm/replace_if.hpp"
#include "etl/_algorithm/search.hpp"
#include "etl/_algorithm/search_n.hpp"
#include "etl/_algorithm/swap.hpp"
#include "etl/_algorithm/swap_ranges.hpp"
#include "etl/_algorithm/transform.hpp"
#include "etl/_concepts/emulation.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_utility/pair.hpp"

// #include "etl/functional.hpp"
#include "etl/iterator.hpp"

namespace etl {

/// \brief Returns the greater of a and b.
/// \group max
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (a < b) ? b : a;
}

/// \brief Returns the greater of a and b, using a compare function.
/// \group max
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto max(
    Type const& a, Type const& b, Compare comp) noexcept -> Type const&
{
    return (comp(a, b)) ? b : a;
}

/// \brief Finds the greatest element in the range `[first, last)`. Elements are
/// compared using operator<.
/// \group max_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto max_element(
    ForwardIt first, ForwardIt last) noexcept -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt largest = first;
    ++first;
    for (; first != last; ++first) {
        if (*largest < *first) { largest = first; }
    }
    return largest;
}

/// \brief Finds the greatest element in the range `[first, last)`. Elements are
/// compared using the given binary comparison function comp.
/// \group max_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto max_element(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt largest = first;
    ++first;
    for (; first != last; ++first) {
        if (comp(*largest, *first)) { largest = first; }
    }
    return largest;
}

/// \brief Returns the smaller of a and b.
/// \group min
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (b < a) ? b : a;
}

/// \brief Returns the smaller of a and b, using a compare function.
/// \group min
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto min(
    Type const& a, Type const& b, Compare comp) noexcept -> Type const&
{
    return (comp(b, a)) ? b : a;
}

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using operator<.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last) noexcept -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (*first < *smallest) { smallest = first; }
    }
    return smallest;
}

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using the given binary comparison function comp.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (comp(*first, *smallest)) { smallest = first; }
    }
    return smallest;
}

/// \brief Returns the lowest and the greatest of the given values.
/// \group minmax
/// \module Algorithm
template <typename T, typename Compare>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b, Compare comp)
    -> pair<T const&, T const&>
{
    using return_type = pair<T const&, T const&>;
    return comp(b, a) ? return_type(b, a) : return_type(a, b);
}

/// \brief Returns the lowest and the greatest of the given values.
/// \group minmax
/// \module Algorithm
template <typename T>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b)
    -> pair<T const&, T const&>
{
    return minmax(a, b, less<> {});
}

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \group minmax_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto minmax_element(
    ForwardIt first, ForwardIt last, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    auto min = first;
    auto max = first;

    if (first == last || ++first == last) { return { min, max }; }

    if (comp(*first, *min)) {
        min = first;
    } else {
        max = first;
    }

    while (++first != last) {
        auto i = first;
        if (++first == last) {
            if (comp(*i, *min)) {
                min = i;
            } else if (!(comp(*i, *max))) {
                max = i;
            }
            break;
        }

        if (comp(*first, *i)) {
            if (comp(*first, *min)) { min = first; }
            if (!(comp(*i, *max))) { max = i; }
        } else {
            if (comp(*i, *min)) { min = i; }
            if (!(comp(*first, *max))) { max = first; }
        }
    }

    return { min, max };
}

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \group minmax_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last)
    -> pair<ForwardIt, ForwardIt>
{
    using value_type = typename iterator_traits<ForwardIt>::value_type;
    return minmax_element(first, last, less<value_type>());
}

/// \brief If v compares less than lo, returns lo; otherwise if hi compares less
/// than v, returns hi; otherwise returns v. Uses operator< to compare the
/// values.
///
/// \group clamp
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto clamp(
    Type const& v, Type const& lo, Type const& hi) noexcept -> Type const&
{
    return clamp(v, lo, hi, less<Type>());
}
/// \group clamp
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto clamp(
    Type const& v, Type const& lo, Type const& hi, Compare comp) -> Type const&
{
    TETL_ASSERT(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

/// \brief Checks if unary predicate p returns true for all elements in the
/// range `[first, last)`.
/// \complexity At most `last - first` applications of the predicate.
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto all_of(InputIt first, InputIt last, Predicate p)
    -> bool
{
    return find_if_not(first, last, p) == last;
}

/// \brief Checks if unary predicate p returns true for at least one element in
/// the range `[first, last)`.
/// \complexity At most `last - first` applications of the predicate.
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto any_of(InputIt first, InputIt last, Predicate p)
    -> bool
{
    return find_if(first, last, p) != last;
}

/// \brief Checks if unary predicate p returns true for no elements in the range
/// `[first, last)`.
/// \complexity At most `last - first` applications of the predicate.
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last, Predicate p)
    -> bool
{
    return find_if(first, last, p) == last;
}

/// \brief Reverses the order of the elements in the range `[first, last)`.
/// Behaves as if applying iter_swap to every pair of iterators `first + i`,
/// `(last-i) - 1` for each non-negative `i < (last - first) / 2`.
///
/// \module Algorithm
template <typename BidirIt>
constexpr auto reverse(BidirIt first, BidirIt last) -> void
{
    while ((first != last) && (first != --last)) { iter_swap(first++, last); }
}

/// \brief Copies the elements from the range `[first, last)` to another range
/// beginning at d_first in such a way that the elements in the new range are in
/// reverse order.
/// \details If the source and destination ranges (that is, `[first, last)` and
/// [d_first, d_first+(last-first)) respectively) overlap, the behavior is
/// undefined.
///
/// \module Algorithm
template <typename BidirIt, typename OutputIt>
constexpr auto reverse_copy(BidirIt first, BidirIt last, OutputIt destination)
    -> OutputIt
{
    for (; first != last; ++destination) { *(destination) = *(--last); }
    return destination;
}

/// \brief Performs a left rotation on a range of elements.
/// \details Specifically, rotate swaps the elements in the range [first,
/// last) in such a way that the element n_first becomes the first element of
/// the new range and n_first - 1 becomes the last element. A precondition of
/// this function is that [first, n_first) and [n_first, last) are valid ranges.
///
/// \module Algorithm
template <typename ForwardIt>
constexpr auto rotate(ForwardIt first, ForwardIt nFirst, ForwardIt last)
    -> ForwardIt
{
    if (first == nFirst) { return last; }
    if (nFirst == last) { return first; }

    auto read     = nFirst;
    auto write    = first;
    auto nextRead = first;

    while (read != last) {
        if (write == nextRead) { nextRead = read; }
        iter_swap(write++, read++);
    }

    rotate(write, nextRead, last);
    return write;
}

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
constexpr auto unique(ForwardIt first, ForwardIt last, Predicate pred)
    -> ForwardIt
{
    if (first == last) { return last; }

    auto result = first;
    while (++first != last) {
        if (!pred(*result, *first) && ++result != first) {
            *result = move(*first);
        }
    }
    return ++result;
}

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt>
constexpr auto unique(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return unique(first, last, equal_to<> {});
}

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using the given binary predicate pred. The
/// behavior is undefined if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination,
    Predicate pred) -> OutputIt
{
    if (first != last) {
        *destination = *first;

        while (++first != last) {
            if (!pred(*destination, *first)) { *++destination = *first; }
        }

        ++destination;
    }

    return destination;
}

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using operator==. The behavior is undefined
/// if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    return unique_copy(first, last, destination, equal_to<> {});
}

/// \brief Reorders the elements in the range `[first, last)` in such a way that
/// all elements for which the predicate p returns true precede the elements for
/// which predicate p returns false. Relative order of the elements is not
/// preserved.
///
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
constexpr auto partition(ForwardIt first, ForwardIt last, Predicate p)
    -> ForwardIt
{
    first = find_if_not(first, last, p);
    if (first == last) { return first; }

    for (ForwardIt i = next(first); i != last; ++i) {
        if (p(*i)) {
            iter_swap(i, first);
            ++first;
        }
    }
    return first;
}

/// \brief Copies the elements from the range `[first, last)` to two different
/// ranges depending on the value returned by the predicate p. The elements that
/// satisfy the predicate p are copied to the range beginning at
/// destination_true. The rest of the elements are copied to the range beginning
/// at destination_false.
/// \details The behavior is undefined if the input range overlaps either of the
/// output ranges.
///
/// \module Algorithm
template <typename InputIt, typename OutputIt1, typename OutputIt2,
    typename Predicate>
constexpr auto partition_copy(InputIt first, InputIt last,
    OutputIt1 destinationTrue, OutputIt2 destinationFalse, Predicate p)
    -> pair<OutputIt1, OutputIt2>
{
    for (; first != last; ++first) {
        if (p(*first)) {
            *destinationTrue = *first;
            ++destinationTrue;
        } else {
            *destinationFalse = *first;
            ++destinationFalse;
        }
    }

    return make_pair(destinationTrue, destinationFalse);
}

/// \brief Returns true if all elements in the range `[first, last)` that
/// satisfy the predicate p appear before all elements that don't. Also returns
/// true if the range is empty.
/// \notes
/// [cppreference.com/w/cpp/algorithm/is_partitioned](https://en.cppreference.com/w/cpp/algorithm/is_partitioned)
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto is_partitioned(
    InputIt first, InputIt last, Predicate p) -> bool
{
    for (; first != last; ++first) {
        if (!p(*first)) { break; }
    }

    for (; first != last; ++first) {
        if (p(*first)) { return false; }
    }

    return true;
}

/// \brief Examines the partitioned (as if by partition) range [first,
/// last) and locates the end of the first partition, that is, the first
/// element that does not satisfy p or last if all elements satisfy p.
///
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto partition_point(
    ForwardIt first, ForwardIt last, Predicate p) -> ForwardIt
{
    for (; first != last; ++first) {
        if (!p(*first)) { break; }
    }

    return first;
}

/// \brief  Reorders the elements in the range `[first, last)` in such a way
/// that all elements for which the predicate p returns true precede the
/// elements for which predicate p returns false. Relative order of the
/// elements is preserved.
///
/// \module Algorithm
template <typename BidirIt, typename Predicate>
constexpr auto stable_partition(BidirIt f, BidirIt l, Predicate p) -> BidirIt
{
    auto const n = l - f;
    if (n == 0) { return f; }
    if (n == 1) { return f + p(*f); }
    auto const m = f + (n / 2);
    return rotate(stable_partition(f, m, p), m, stable_partition(m, l, p));
}

/// \brief Copies the elements in the range, defined by `[first, last)`, to
/// another range beginning at destination.
/// \details Copies all elements in the range `[first, last)` starting from
/// first and proceeding to `last - 1`. The behavior is undefined if destination
/// is within the range `[first, last)`. In this case, copy_backward may be used
/// instead.
/// \returns Output iterator to the element in the destination range, one past
/// the last element copied.
/// \group copy
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto copy(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    for (; first != last; ++first, ++destination) { *destination = *first; }
    return destination;
}

/// \brief Copies the elements in the range, defined by `[first, last)`, to
/// another range beginning at destination.
/// \details Only copies the elements for which the predicate pred returns true.
/// The relative order of the elements that are copied is preserved. The
/// behavior is undefined if the source and the destination ranges overlap.
/// \returns Output iterator to the element in the destination range, one past
/// the last element copied.
/// \group copy
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto copy_if(
    InputIt first, InputIt last, OutputIt dFirst, Predicate pred) -> OutputIt
{
    while (first != last) {
        if (pred(*first)) { *dFirst++ = *first; }
        first++;
    }
    return dFirst;
}

/// \brief Copies exactly count values from the range beginning at first to the
/// range beginning at result. Formally, for each integer `0 <= i < count`,
/// performs `*(result + i) = *(first + i)`. Overlap of ranges is formally
/// permitted, but leads to unpredictable ordering of the results.
///
/// \returns Iterator in the destination range, pointing past the last element
/// copied if count>0 or result otherwise.
///
/// \module Algorithm
template <typename InputIt, typename Size, typename OutputIt>
constexpr auto copy_n(InputIt first, Size count, OutputIt result) -> OutputIt
{
    if (count > 0) {
        *result++ = *first;
        for (Size i = 1; i < count; ++i) { *result++ = *++first; }
    }
    return result;
}

/// \brief Copies the elements from the range, defined by `[first, last)`, to
/// another range ending at `dLast`. The elements are copied in reverse order
/// (the last element is copied first), but their relative order is preserved.
///
/// \details The behavior is undefined if `dLast` is within `(first, last]`.
/// copy must be used instead of copy_backward in that case.
///
/// \returns Iterator to the last element copied.
///
/// \module Algorithm
template <typename BidirIt1, typename BidirIt2>
constexpr auto copy_backward(BidirIt1 first, BidirIt1 last, BidirIt2 dLast)
    -> BidirIt2
{
    while (first != last) { *(--dLast) = *(--last); }
    return dLast;
}

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at destination in such a way, that the element `nFirst` becomes
/// the first element of the new range and `nFirst - 1` becomes the last
/// element.
///
/// \module Algorithm
template <typename ForwardIt, typename OutputIt>
constexpr auto rotate_copy(ForwardIt first, ForwardIt nFirst, ForwardIt last,
    OutputIt destination) -> OutputIt
{
    destination = copy(nFirst, last, destination);
    return copy(first, nFirst, destination);
}

/// \brief Shifts the elements in the range [first, last) by n positions.
///
/// \details Shifts the elements towards the beginning of the range. If n == 0
/// || n >= last - first, there are no effects. If n < 0, the behavior is
/// undefined. Otherwise, for every integer i in [0, last - first - n), moves
/// the element originally at position first + n + i to position first + i. The
/// moves are performed in increasing order of i starting from ​0​.
template <typename ForwardIt>
constexpr auto shift_left(ForwardIt first, const ForwardIt last,
    typename iterator_traits<ForwardIt>::difference_type n) -> ForwardIt
{
    if (n <= 0) { return last; }
    auto start = first;
    if constexpr (detail::RandomAccessIterator<ForwardIt>) {
        if (n >= last - first) { return first; }
        start += n;
    } else {
        for (; 0 < n; --n) {
            if (start == last) { return first; }
            ++start;
        }
    }

    first = move(start, last, first);
    return first;
}

/// \brief Assigns the given value to the elements in the range `[first, last)`.
///
/// \module Algorithm
template <typename ForwardIt, typename T>
constexpr auto fill(ForwardIt first, ForwardIt last, T const& value) -> void
{
    for (; first != last; ++first) { *first = value; }
}

/// \brief Assigns the given value to the first count elements in the range
/// beginning at `first` if `count > 0`. Does nothing otherwise.
///
/// \returns Iterator one past the last element assigned if `count > 0`, `first`
/// otherwise.
///
/// \module Algorithm
template <typename OutputIt, typename Size, typename T>
constexpr auto fill_n(OutputIt first, Size count, T const& value) -> OutputIt
{
    for (auto i = Size { 0 }; i < count; ++i) {
        *first = value;
        ++first;
    }

    return first;
}

/// \brief Returns true if the range `[first1, last1)` is equal to the range
/// `[first2, first2 + (last1 - first1))`, and false otherwise.
///
/// \group equal
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, Predicate p) -> bool
{
    for (; first1 != last1; ++first1, ++first2) {
        if (!p(*first1, *first2)) { return false; }
    }
    return true;
}

/// \group equal
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2) -> bool
{
    return equal(first1, last1, first2, equal_to<> {});
}

/// \group equal
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2, Predicate p) -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return equal(first1, last1, first2, p);
}

/// \group equal
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return equal(first1, last1, first2, last2, equal_to<> {});
}

/// \brief Checks if the first range `[first1, last1)` is lexicographically
/// less than the second range `[first2, last2)`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/lexicographical_compare](https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare)
///
/// \group lexicographical_compare
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 first1,
    InputIt1 last1, InputIt2 first2, InputIt2 last2, Compare comp) -> bool
{
    for (; (first1 != last1) && (first2 != last2); ++first1, (void)++first2) {
        if (comp(*first1, *first2)) { return true; }
        if (comp(*first2, *first1)) { return false; }
    }
    return (first1 == last1) && (first2 != last2);
}

/// \group lexicographical_compare
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto lexicographical_compare(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return lexicographical_compare(
        first1, last1, first2, last2, less<decltype(*first1)> {});
}

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equal elements is not guaranteed to be preserved.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/sort](https://en.cppreference.com/w/cpp/algorithm/sort)
///
/// \group sort
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i != last; ++i) {
        for (auto j = first; j < i; ++j) {
            if (comp(*i, *j)) { iter_swap(i, j); }
        }
    }
}

/// \group sort
template <typename RandomIt>
constexpr auto sort(RandomIt first, RandomIt last) -> void
{
    sort(first, last, less<> {});
}

/// \brief Sorts the elements in the range `[first, last)` in non-descending
/// order. The order of equivalent elements is guaranteed to be preserved.
/// Elements are compared using the given comparison function comp.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/stable_sort](https://en.cppreference.com/w/cpp/algorithm/stable_sort)
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

/// \brief Rearranges elements such that the range `[first, middle)` contains
/// the sorted `middle - first` smallest elements in the range `[first, last)`.
/// The order of equal elements is not guaranteed to be preserved. The order of
/// the remaining elements in the range `[middle, last)` is unspecified.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/partial_sort](https://en.cppreference.com/w/cpp/algorithm/partial_sort)
///
/// \group partial_sort
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto partial_sort(
    RandomIt first, RandomIt middle, RandomIt last, Compare comp) -> void
{
    // TODO: Improve. Currently forwards to regular sort.
    etl::ignore_unused(middle);
    etl::sort(first, last, comp);
}

/// \group partial_sort
template <typename RandomIt>
constexpr auto partial_sort(RandomIt first, RandomIt middle, RandomIt last)
    -> void
{
    etl::ignore_unused(middle);
    etl::sort(first, last);
}

/// \brief nth_element is a partial sorting algorithm that rearranges elements
/// in `[first, last)` such that:
/// - The element pointed at by nth is changed to whatever element would occur
/// in that position if `[first, last)` were sorted.
/// - All of the elements before this new nth element are less than or equal to
/// the elements after the new nth element.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/nth_element](https://en.cppreference.com/w/cpp/algorithm/nth_element)
///
/// \group nth_element
/// \module Algorithm
template <typename RandomIt, typename Compare>
constexpr auto nth_element(
    RandomIt first, RandomIt nth, RandomIt last, Compare comp) -> void
{
    // TODO: Improve. Currently forwards to regular sort.
    etl::ignore_unused(nth);
    etl::sort(first, last, comp);
}

/// \group nth_element
template <typename RandomIt>
constexpr auto nth_element(RandomIt first, RandomIt nth, RandomIt last) -> void
{
    etl::ignore_unused(nth);
    etl::sort(first, last);
}

/// \brief Examines the range `[first, last)` and finds the largest range
/// beginning at `first` in which the elements are sorted in non-descending
/// order.
///
/// \group is_sorted_until
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIt first, ForwardIt last)
    -> ForwardIt
{
    return is_sorted_until(first, last, less<>());
}

/// \group is_sorted_until
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted_until(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first != last) {
        ForwardIt next = first;
        while (++next != last) {
            if (comp(*next, *first)) { return next; }
            first = next;
        }
    }
    return last;
}

/// \brief Checks if the elements in range `[first, last)` are sorted in
/// non-descending order.
///
/// \group is_sorted
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted(ForwardIt first, ForwardIt last) -> bool
{
    return is_sorted_until(first, last) == last;
}

/// \group is_sorted
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted(
    ForwardIt first, ForwardIt last, Compare comp) -> bool
{
    return is_sorted_until(first, last, comp) == last;
}

/// \brief Returns an iterator pointing to the first element in the range
/// `[first, last)` that is not less than (i.e. greater or equal to) value, or
/// last if no such element is found.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/lower_bound](https://en.cppreference.com/w/cpp/algorithm/lower_bound)
///
/// \group lower_bound
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto lower_bound(ForwardIt first, ForwardIt last,
    T const& value, Compare comp) noexcept -> ForwardIt
{
    using diff_t = typename iterator_traits<ForwardIt>::difference_type;
    ForwardIt it;
    diff_t count;
    diff_t step;
    count = distance(first, last);

    while (count > 0) {
        it   = first;
        step = count / 2;
        advance(it, step);
        if (comp(*it, value)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

/// \group lower_bound
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto lower_bound(
    ForwardIt first, ForwardIt last, T const& value) noexcept -> ForwardIt
{
    return lower_bound(first, last, value, less<> {});
}

/// \brief Returns an iterator pointing to the first element in the range
/// `[first, last)` that is greater than `value`, or last if no such element is
/// found.
///
/// \details The range `[first, last)` must be partitioned with respect to the
/// expression `!(value < element)` or `!comp(value, element)`, i.e., all
/// elements for which the expression is true must precede all elements for
/// which the expression is false. A fully-sorted range meets this criterion.
///
/// \group upper_bound
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto upper_bound(
    ForwardIt first, ForwardIt last, T const& value, Compare comp) -> ForwardIt
{
    using diff_t = typename iterator_traits<ForwardIt>::difference_type;

    ForwardIt it;
    diff_t count;
    diff_t step;
    count = distance(first, last);

    while (count > 0) {
        it   = first;
        step = count / 2;
        advance(it, step);
        if (!comp(value, *it)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

/// \group upper_bound
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto upper_bound(
    ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return upper_bound(first, last, value, less<> {});
}

/// \brief Returns a range containing all elements equivalent to value in the
/// range `[first, last)`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/equal_range](https://en.cppreference.com/w/cpp/algorithm/equal_range)
///
/// \group equal_range
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    return make_pair(lower_bound(first, last, value, comp),
        upper_bound(first, last, value, comp));
}

/// \group equal_range
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value) -> pair<ForwardIt, ForwardIt>
{
    return equal_range(first, last, value, less<> {});
}

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