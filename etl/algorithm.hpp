/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

/**
 * @example algorithm.cpp
 */

#ifndef TAETL_ALGORITHM_HPP
#define TAETL_ALGORITHM_HPP

#include "cassert.hpp"
#include "definitions.hpp"
#include "functional.hpp"

namespace etl
{
/**
 * @brief Exchanges the given values. Swaps the values a and b. This overload
 * does not participate in overload resolution unless
 * etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T> is true.
 *
 * @todo Fix noexcept specifier.
 * @ref https://en.cppreference.com/w/cpp/algorithm/swap
 */
template <class T>
constexpr auto swap(T& a, T& b) noexcept -> void
{
    auto temp = a;
    a         = b;
    b         = temp;
}

/**
 * @brief Swaps the values of the elements the given iterators are pointing to.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/iter_swap
 */
template <class ForwardIt1, class ForwardIt2>
constexpr auto iter_swap(ForwardIt1 a, ForwardIt2 b) -> void
{
    using etl::swap;
    swap(*a, *b);
}

/**
 * @brief Applies the given function object f to the result of dereferencing
 * every iterator in the range [first, last] in order.
 */
template <class InputIt, class UnaryFunction>
constexpr auto for_each(InputIt first, InputIt last, UnaryFunction f) noexcept
    -> UnaryFunction
{
    for (; first != last; ++first) { f(*first); }
    return f;
}

/**
 * @brief Applies the given function object f to the result of dereferencing
 * every iterator in the range [first, first+n] in order.
 */
template <class InputIt, class Size, class UnaryFunction>
constexpr auto for_each_n(InputIt first, Size n, UnaryFunction f) noexcept -> InputIt
{
    for (Size i = 0; i < n; ++first, (void)++i) { f(*first); }
    return first;
}

/**
 * @brief Searches for an element equal to value.
 */
template <class InputIt, class T>
[[nodiscard]] constexpr auto find(InputIt first, InputIt last, const T& value) noexcept
    -> InputIt
{
    for (; first != last; ++first)
    {
        if (*first == value) { return first; }
    }
    return last;
}

/**
 * @brief Searches for an element for which predicate p returns true
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto find_if(InputIt first, InputIt last,
                                     UnaryPredicate p) noexcept -> InputIt
{
    for (; first != last; ++first)
    {
        if (p(*first)) { return first; }
    }
    return last;
}

/**
 * @brief Searches for an element for which predicate q returns false
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto find_if_not(InputIt first, InputIt last,
                                         UnaryPredicate q) noexcept -> InputIt
{
    for (; first != last; ++first)
    {
        if (!q(*first)) { return first; }
    }
    return last;
}

/**
 * @brief Returns the greater of a and b.
 */
template <class Type>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b) noexcept -> Type const&
{
    return (a < b) ? b : a;
}

/**
 * @brief Returns the greater of a and b, using a compare function.
 */
template <class Type, class Compare>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b, Compare comp) noexcept
    -> Type const&
{
    return (comp(a, b)) ? b : a;
}

/**
 * @brief Finds the greatest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <class ForwardIterator>
[[nodiscard]] constexpr auto max_element(ForwardIterator first,
                                         ForwardIterator last) noexcept -> ForwardIterator
{
    if (first == last) { return last; }

    ForwardIterator largest = first;
    ++first;
    for (; first != last; ++first)
    {
        if (*largest < *first) { largest = first; }
    }
    return largest;
}

/**
 * @brief Finds the greatest element in the range [first, last). Elements are
 * compared using the given binary comparison function comp.
 */
template <class ForwardIterator, class Compare>
[[nodiscard]] constexpr auto max_element(ForwardIterator first, ForwardIterator last,
                                         Compare comp) -> ForwardIterator
{
    if (first == last) { return last; }

    ForwardIterator largest = first;
    ++first;
    for (; first != last; ++first)
    {
        if (comp(*largest, *first)) { largest = first; }
    }
    return largest;
}

/**
 * @brief Returns the smaller of a and b.
 */
template <class Type>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept -> Type const&
{
    return (b < a) ? b : a;
}

/**
 * @brief Returns the smaller of a and b, using a compare function.
 */
template <class Type, class Compare>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b, Compare comp) noexcept
    -> Type const&
{
    return (comp(b, a)) ? b : a;
}

/**
 * @brief Finds the smallest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <class ForwardIterator>
[[nodiscard]] constexpr auto min_element(ForwardIterator first,
                                         ForwardIterator last) noexcept -> ForwardIterator
{
    if (first == last) { return last; }

    ForwardIterator smallest = first;
    ++first;
    for (; first != last; ++first)
    {
        if (*first < *smallest) { smallest = first; }
    }
    return smallest;
}

/**
 * @brief Finds the smallest element in the range [first, last). Elements are
 * compared using the given binary comparison function comp.
 */
template <class ForwardIterator, class Compare>
[[nodiscard]] constexpr auto min_element(ForwardIterator first, ForwardIterator last,
                                         Compare comp) -> ForwardIterator
{
    if (first == last) { return last; }

    ForwardIterator smallest = first;
    ++first;
    for (; first != last; ++first)
    {
        if (comp(*first, *smallest)) { smallest = first; }
    }
    return smallest;
}

/**
 * @brief If v compares less than lo, returns lo; otherwise if hi compares less
 * than v, returns hi; otherwise returns v. Uses operator< to compare the
 * values.
 */
template <class Type>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi) noexcept
    -> Type const&
{
    return clamp(v, lo, hi, etl::less<Type>());
}

template <class Type, class Compare>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi,
                                   Compare comp) -> Type const&
{
    ETL_ASSERT(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

/**
 * @brief Checks if unary predicate p returns true for all elements in the range
 * [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto all_of(InputIt first, InputIt last, UnaryPredicate p) -> bool
{
    return etl::find_if_not(first, last, p) == last;
}

/**
 * @brief Checks if unary predicate p returns true for at least one element in
 * the range [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto any_of(InputIt first, InputIt last, UnaryPredicate p) -> bool
{
    return etl::find_if(first, last, p) != last;
}

/**
 * @brief Checks if unary predicate p returns true for no elements in the range
 * [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last, UnaryPredicate p)
    -> bool
{
    return etl::find_if(first, last, p) == last;
}

/**
 * @brief Performs a left rotation on a range of elements.
 *
 * @details Specifically, etl::rotate swaps the elements in the range [first,
 * last) in such a way that the element n_first becomes the first element of the
 * new range and n_first - 1 becomes the last element. A precondition of this
 * function is that [first, n_first) and [n_first, last) are valid ranges.
 */
template <class ForwardIt>
constexpr auto rotate(ForwardIt first, ForwardIt n_first, ForwardIt last) -> ForwardIt
{
    if (first == n_first) { return last; }
    if (n_first == last) { return first; }

    ForwardIt read      = n_first;
    ForwardIt write     = first;
    ForwardIt next_read = first;  // read position for when "read" hits "last"

    while (read != last)
    {
        if (write == next_read)
        {
            next_read = read;  // track where "first" went
        }
        etl::iter_swap(write++, read++);
    }

    // rotate the remaining sequence into place
    (rotate)(write, next_read, last);
    return write;
}

/**
 * @brief  Reorders the elements in the range [first, last) in such a way
 * that all elements for which the predicate p returns true precede the
 * elements for which predicate p returns false. Relative order of the
 * elements is preserved.
 */
template <class BidirIt, class UnaryPredicate>
constexpr auto stable_partition(BidirIt f, BidirIt l, UnaryPredicate p) -> BidirIt
{
    auto const n = l - f;
    if (n == 0) { return f; }
    if (n == 1) { return f + p(*f); }
    auto const m = f + (n / 2);
    return rotate(stable_partition(f, m, p), m, stable_partition(m, l, p));
}

/**
 * @brief Copies the elements in the range, defined by [first, last), to another range
 * beginning at destination.
 *
 * @details Copies all elements in the range [first, last) starting from first and
 * proceeding to last - 1. The behavior is undefined if destination is within the range
 * [first, last). In this case, etl::copy_backward may be used instead.
 *
 * @return Output iterator to the element in the destination range, one past the last
 * element copied.
 */
template <class InputIt, class OutputIt>
constexpr auto copy(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    for (; first != last; ++first, ++destination) { *destination = *first; }
    return destination;
}

/**
 * @brief Copies the elements in the range, defined by [first, last), to another range
 * beginning at destination.
 *
 * @details Only copies the elements for which the predicate pred returns true. The
 * relative order of the elements that are copied is preserved. The behavior is undefined
 * if the source and the destination ranges overlap.
 *
 * @return Output iterator to the element in the destination range, one past the last
 * element copied.
 */
template <class InputIt, class OutputIt, class UnaryPredicate>
constexpr auto copy_if(InputIt first, InputIt last, OutputIt d_first, UnaryPredicate pred)
    -> OutputIt
{
    while (first != last)
    {
        if (pred(*first)) { *d_first++ = *first; }
        first++;
    }
    return d_first;
}

/**
 * @brief Copies exactly count values from the range beginning at first to the range
 * beginning at result. Formally, for each integer 0 ≤ i < count, performs *(result + i) =
 * *(first + i). Overlap of ranges is formally permitted, but leads to unpredictable
 * ordering of the results.
 *
 * @return Iterator in the destination range, pointing past the last element copied if
 * count>0 or result otherwise.
 */
template <class InputIt, class Size, class OutputIt>
constexpr auto copy_n(InputIt first, Size count, OutputIt result) -> OutputIt
{
    if (count > 0)
    {
        *result++ = *first;
        for (Size i = 1; i < count; ++i) { *result++ = *++first; }
    }
    return result;
}

/**
 * @brief Checks if the first range [first1, last1) is lexicographically
 * less than the second range [first2, last2). Elements are compared using
 * the given binary comparison function comp.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare
 */
template <class InputIt1, class InputIt2, class Compare>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 first1, InputIt1 last1,
                                                     InputIt2 first2, InputIt2 last2,
                                                     Compare comp) -> bool
{
    for (; (first1 != last1) && (first2 != last2); ++first1, (void)++first2)
    {
        if (comp(*first1, *first2)) { return true; }
        if (comp(*first2, *first1)) { return false; }
    }
    return (first1 == last1) && (first2 != last2);
}

/**
 * @brief Checks if the first range [first1, last1) is lexicographically
 * less than the second range [first2, last2). Elements are compared using
 * operator<.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare
 */
template <class InputIt1, class InputIt2>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 first1, InputIt1 last1,
                                                     InputIt2 first2, InputIt2 last2)
    -> bool
{
    return lexicographical_compare(first1, last1, first2, last2,
                                   etl::less<decltype(*first1)> {});
}

}  // namespace etl

#endif  // TAETL_ALGORITHM_HPP