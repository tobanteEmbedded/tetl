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

#include "etl/cassert.hpp"
#include "etl/definitions.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/type_traits.hpp"

#include "etl/detail/algo_search.hpp"

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
template <typename T>
constexpr auto swap(T& a, T& b) noexcept -> void
{
    T temp(etl::move(a));
    a = etl::move(b);
    b = etl::move(temp);
}

/**
 * @brief Swaps the values of the elements the given iterators are pointing to.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/iter_swap
 */
template <typename ForwardIt1, typename ForwardIt2>
constexpr auto iter_swap(ForwardIt1 a, ForwardIt2 b) -> void
{
    using etl::swap;
    swap(*a, *b);
}

/**
 * @brief Moves the elements in the range [first, last), to another range beginning at
 * d_first, starting from first and proceeding to last - 1. After this operation the
 * elements in the moved-from range will still contain valid values of the appropriate
 * type, but not necessarily the same values as before the move.
 */
template <typename InputIter, typename OutputIter>
constexpr auto move(InputIter first, InputIter last, OutputIter destination) -> OutputIter
{
    for (; first != last; ++first, ++destination) { *destination = ::etl::move(*first); }
    return destination;
}

/**
 * @brief Applies the given function object f to the result of dereferencing
 * every iterator in the range [first, last] in order.
 */
template <typename InputIt, typename UnaryFunction>
constexpr auto for_each(InputIt first, InputIt last, UnaryFunction f) noexcept
    -> UnaryFunction
{
    for (; first != last; ++first) { f(*first); }
    return f;
}

/**
 * @brief Applies the given function object \p f to the result of dereferencing
 * every iterator in the range [ \p first, first+n] in order.
 */
template <typename InputIter, typename Size, typename UnaryFunction>
constexpr auto for_each_n(InputIter first, Size n, UnaryFunction f) noexcept -> InputIter
{
    for (Size i = 0; i < n; ++first, ++i) { f(*first); }
    return first;
}

/**
 * @brief Applies the given function to a range and stores the result in
 * another range, beginning at \p destination. The unary operation unary_op is applied to
 * the range defined by [ \p first, \p last ).
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/transform
 */
template <typename InputIter, typename OutputIter, typename UnaryOperation>
constexpr auto transform(InputIter first, InputIter last, OutputIter destination,
                         UnaryOperation op) -> OutputIter
{
    for (; first != last; ++first, ++destination) { *destination = op(*first); }
    return destination;
}

/**
 * @brief Applies the given function to a range and stores the result in
 * another range, beginning at destination. The binary operation binary_op is applied to
 * pairs of elements from two ranges: one defined by [first1, last1) and the other
 * beginning at first2.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/transform
 */
template <typename InputIter1, typename InputIter2, typename OutputIter,
          typename BinaryOperation>
constexpr auto transform(InputIter1 first1, InputIter1 last1, InputIter2 first2,
                         OutputIter dest, BinaryOperation op) -> OutputIter
{
    for (; first1 != last1; ++first1, ++first2, ++dest) { *dest = op(*first1, *first2); }
    return dest;
}

/**
 * @brief Assigns each element in range [first, last) a value generated by the given
 * function object g.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/generate
 */
template <typename ForwardIt, typename Generator>
constexpr auto generate(ForwardIt first, ForwardIt last, Generator g) -> void
{
    for (; first != last; ++first) { *first = g(); }
}

/**
 * @brief Assigns values, generated by given function object g, to the first count
 * elements in the range beginning at first, if count>0. Does nothing otherwise.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/generate_n
 */
template <typename OutputIt, typename SizeT, typename Generator>
constexpr auto generate_n(OutputIt first, SizeT count, Generator g) -> OutputIt
{
    for (; count > 0; ++first, --count) { *first = g(); }
    return first;
}

/**
 * @brief Returns the number of elements in the range [first, last) satisfying specific
 * criteria. Counts the elements that are equal to value.
 */
template <typename InputIter, typename T>
[[nodiscard]] constexpr auto count(InputIter first, InputIter last, const T& value) ->
    typename iterator_traits<InputIter>::difference_type
{
    auto result = typename iterator_traits<InputIter>::difference_type {0};
    for (; first != last; ++first)
    {
        if (*first == value) { ++result; }
    }
    return result;
}

/**
 * @brief Returns the number of elements in the range [first, last) satisfying
 * specific criteria. Counts elements for which predicate p returns true.
 */
template <typename InputIter, typename UnaryPredicate>
[[nodiscard]] constexpr auto count_if(InputIter first, InputIter last, UnaryPredicate p)
    -> typename iterator_traits<InputIter>::difference_type
{
    auto result = typename iterator_traits<InputIter>::difference_type {0};
    for (; first != last; ++first)
    {
        if (p(*first)) { ++result; }
    }
    return result;
}

/**
 * @brief Returns the first mismatching pair of elements from two ranges: one defined by
 * [first1, last1) and another defined by [first2,last2). If last2 is not provided
 * (overloads (1-4)), it denotes first2 + (last1 - first1).
 *
 * @details Elements are compared using the given binary predicate p.
 */
template <class InputIter1, class InputIter2, class BinaryPredicate>
[[nodiscard]] constexpr auto mismatch(InputIter1 first1, InputIter1 last1,
                                      InputIter2 first2, BinaryPredicate pred)
    -> etl::pair<InputIter1, InputIter2>
{
    for (; first1 != last1; ++first1, ++first2)
    {
        if (!pred(*first1, *first2)) { break; }
    }

    return etl::pair<InputIter1, InputIter2>(first1, first2);
}

/**
 * @brief Returns the first mismatching pair of elements from two ranges: one defined
 * by [first1, last1) and another defined by [first2,last2). If last2 is not provided
 * (overloads (1-4)), it denotes first2 + (last1 - first1).
 *
 * @details Elements are compared using operator==.
 */
template <class InputIter1, class InputIter2>
[[nodiscard]] constexpr auto mismatch(InputIter1 first1, InputIter1 last1,
                                      InputIter2 first2)
    -> etl::pair<InputIter1, InputIter2>
{
    return mismatch(first1, last1, first2, etl::equal_to<> {});
}

/**
 * @brief Returns the first mismatching pair of elements from two ranges: one defined by
 * [first1, last1) and another defined by [first2,last2). If last2 is not provided
 * (overloads (1-4)), it denotes first2 + (last1 - first1).
 *
 * @details Elements are compared using the given binary predicate p.
 */
template <class InputIter1, class InputIter2, class BinaryPredicate>
[[nodiscard]] constexpr auto mismatch(InputIter1 first1, InputIter1 last1,
                                      InputIter2 first2, InputIter2 last2,
                                      BinaryPredicate pred)
    -> etl::pair<InputIter1, InputIter2>
{
    for (; first1 != last1 && first2 != last2; ++first1, ++first2)
    {
        if (!pred(*first1, *first2)) { break; }
    }

    return etl::pair<InputIter1, InputIter2>(first1, first2);
}

/**
 * @brief Returns the first mismatching pair of elements from two ranges: one defined
 * by [first1, last1) and another defined by [first2,last2). If last2 is not provided
 * (overloads (1-4)), it denotes first2 + (last1 - first1).
 *
 * @details Elements are compared using operator==.
 */
template <class InputIter1, class InputIter2>
[[nodiscard]] constexpr auto mismatch(InputIter1 first1, InputIter1 last1,
                                      InputIter2 first2, InputIter2 last2)
    -> etl::pair<InputIter1, InputIter2>
{
    return mismatch(first1, last1, first2, last2, etl::equal_to<> {});
}

/**
 * @brief Searches for an element equal to value.
 */
template <typename InputIter, typename T>
[[nodiscard]] constexpr auto find(InputIter first, InputIter last,
                                  T const& value) noexcept -> InputIter
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
template <typename InputIter, typename UnaryPredicate>
[[nodiscard]] constexpr auto find_if(InputIter first, InputIter last,
                                     UnaryPredicate p) noexcept -> InputIter
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
template <typename InputIter, typename UnaryPredicate>
[[nodiscard]] constexpr auto find_if_not(InputIter first, InputIter last,
                                         UnaryPredicate predicate) noexcept -> InputIter
{
    for (; first != last; ++first)
    {
        if (!predicate(*first)) { return first; }
    }
    return last;
}

/**
 * @brief Searches for the first occurrence of the sequence of elements [s_first, s_last)
 * in the range [first, last). Elements are compared using the given binary predicate \p
 * pred.
 */
template <class ForwardIter1, class ForwardIter2, class BinaryPredicate>
[[nodiscard]] constexpr auto search(ForwardIter1 first, ForwardIter1 last,
                                    ForwardIter2 s_first, ForwardIter2 s_last,
                                    BinaryPredicate pred) -> ForwardIter1
{
    return detail::search_impl(first, last, s_first, s_last, pred);
}

/**
 * @brief Searches for the first occurrence of the sequence of elements [s_first, s_last)
 * in the range [first, last). Elements are compared using operator==.
 */
template <class ForwardIter1, class ForwardIter2>
[[nodiscard]] constexpr auto search(ForwardIter1 first, ForwardIter1 last,
                                    ForwardIter2 s_first, ForwardIter2 s_last)
    -> ForwardIter1
{
    return search(first, last, s_first, s_last, etl::equal_to<> {});
}

/**
 * @brief Searches the sequence [first, last) for the pattern specified in the constructor
 * of searcher.
 */
template <class ForwardIter, class Searcher>
[[nodiscard]] constexpr auto search(ForwardIter first, ForwardIter last,
                                    Searcher const& searcher) -> ForwardIter
{
    return searcher(first, last).first;
}

/**
 * @brief Returns the greater of a and b.
 */
template <typename Type>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b) noexcept -> Type const&
{
    return (a < b) ? b : a;
}

/**
 * @brief Returns the greater of a and b, using a compare function.
 */
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b, Compare comp) noexcept
    -> Type const&
{
    return (comp(a, b)) ? b : a;
}

/**
 * @brief Finds the greatest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <typename ForwardIterator>
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
template <typename ForwardIterator, typename Compare>
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
template <typename Type>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept -> Type const&
{
    return (b < a) ? b : a;
}

/**
 * @brief Returns the smaller of a and b, using a compare function.
 */
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b, Compare comp) noexcept
    -> Type const&
{
    return (comp(b, a)) ? b : a;
}

/**
 * @brief Finds the smallest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <typename ForwardIterator>
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
template <typename ForwardIterator, typename Compare>
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
 * @brief Finds the smallest and greatest element in the range [first, last).
 */
template <typename ForwardIter, typename Compare>
[[nodiscard]] constexpr auto minmax_element(ForwardIter first, ForwardIter last,
                                            Compare comp)
    -> etl::pair<ForwardIter, ForwardIter>
{
    auto min = first;
    auto max = first;

    if (first == last || ++first == last) { return {min, max}; }

    if (comp(*first, *min)) { min = first; }
    else
    {
        max = first;
    }

    while (++first != last)
    {
        auto i = first;
        if (++first == last)
        {
            if (comp(*i, *min)) { min = i; }
            else if (!(comp(*i, *max)))
            {
                max = i;
            }
            break;
        }

        if (comp(*first, *i))
        {
            if (comp(*first, *min)) { min = first; }
            if (!(comp(*i, *max))) { max = i; }
        }
        else
        {
            if (comp(*i, *min)) { min = i; }
            if (!(comp(*first, *max))) { max = first; }
        }
    }

    return {min, max};
}

/**
 * @brief Finds the smallest and greatest element in the range [first, last).
 */
template <typename ForwardIter>
[[nodiscard]] constexpr auto minmax_element(ForwardIter first, ForwardIter last)
    -> etl::pair<ForwardIter, ForwardIter>
{
    using value_type = typename etl::iterator_traits<ForwardIter>::value_type;
    return etl::minmax_element(first, last, etl::less<value_type>());
}

/**
 * @brief If v compares less than lo, returns lo; otherwise if hi compares less
 * than v, returns hi; otherwise returns v. Uses operator< to compare the
 * values.
 */
template <typename Type>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi) noexcept
    -> Type const&
{
    return clamp(v, lo, hi, etl::less<Type>());
}

template <typename Type, typename Compare>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi,
                                   Compare comp) -> Type const&
{
    assert(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

/**
 * @brief Checks if unary predicate p returns true for all elements in the range
 * [first, last).
 */
template <typename InputIt, typename UnaryPredicate>
[[nodiscard]] constexpr auto all_of(InputIt first, InputIt last, UnaryPredicate p) -> bool
{
    return etl::find_if_not(first, last, p) == last;
}

/**
 * @brief Checks if unary predicate p returns true for at least one element in
 * the range [first, last).
 */
template <typename InputIt, typename UnaryPredicate>
[[nodiscard]] constexpr auto any_of(InputIt first, InputIt last, UnaryPredicate p) -> bool
{
    return etl::find_if(first, last, p) != last;
}

/**
 * @brief Checks if unary predicate p returns true for no elements in the range
 * [first, last).
 */
template <typename InputIt, typename UnaryPredicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last, UnaryPredicate p)
    -> bool
{
    return etl::find_if(first, last, p) == last;
}

/**
 * @brief Reverses the order of the elements in the range [first, last). Behaves as if
 * applying etl::iter_swap to every pair of iterators first+i, (last-i) - 1 for each
 * non-negative i < (last-first)/2.
 */
template <typename BidirIter>
constexpr auto reverse(BidirIter first, BidirIter last) -> void
{
    while ((first != last) && (first != --last)) { etl::iter_swap(first++, last); }
}

/**
 * @brief Copies the elements from the range [ \p first, \p last ) to another range
 * beginning at d_first in such a way that the elements in the new range are in
 * reverse order.
 *
 * @details If the source and destination ranges (that is, [first, last) and [d_first,
 * d_first+(last-first)) respectively) overlap, the behavior is undefined.
 */
template <typename BidirIter, typename OutputIter>
constexpr auto reverse_copy(BidirIter first, BidirIter last, OutputIter destination)
    -> OutputIter
{
    while (first != last) { *(destination++) = *(--last); }
    return destination;
}

/**
 * @brief Performs a left rotation on a range of elements.
 *
 * @details Specifically, etl::rotate swaps the elements in the range [first,
 * last) in such a way that the element n_first becomes the first element of the
 * new range and n_first - 1 becomes the last element. A precondition of this
 * function is that [first, n_first) and [n_first, last) are valid ranges.
 */
template <typename ForwardIt>
constexpr auto rotate(ForwardIt first, ForwardIt n_first, ForwardIt last) -> ForwardIt
{
    if (first == n_first) { return last; }
    if (n_first == last) { return first; }

    auto read      = n_first;
    auto write     = first;
    auto next_read = first;

    while (read != last)
    {
        if (write == next_read) { next_read = read; }
        etl::iter_swap(write++, read++);
    }

    rotate(write, next_read, last);
    return write;
}

/**
 * @brief Eliminates all except the first element from every consecutive group of
 * equivalent elements from the range [first, last) and returns a past-the-end
 * iterator for the new logical end of the range.
 */
template <class ForwardIter, class BinaryPredicate>
constexpr auto unique(ForwardIter first, ForwardIter last, BinaryPredicate pred)
    -> ForwardIter
{
    if (first == last) { return last; }

    auto result = first;
    while (++first != last)
    {
        if (!pred(*result, *first) && ++result != first) { *result = etl::move(*first); }
    }
    return ++result;
}

/**
 * @brief Eliminates all except the first element from every consecutive group of
 * equivalent elements from the range [first, last) and returns a past-the-end
 * iterator for the new logical end of the range.
 */
template <class ForwardIter>
constexpr auto unique(ForwardIter first, ForwardIter last) -> ForwardIter
{
    return unique(first, last, etl::equal_to<> {});
}

/**
 * @brief Copies the elements from the range [first, last), to another range beginning
 * at d_first in such a way that there are no consecutive equal elements. Only the
 * first element of each group of equal elements is copied.
 *
 * @details Elements are compared using the given binary predicate \p pred. The
 * behavior is undefined if it is not an equivalence relation.
 */
template <typename InputIter, typename OutputIter, typename BinaryPredicate>
constexpr auto unique_copy(InputIter first, InputIter last, OutputIter destination,
                           BinaryPredicate pred) -> OutputIter
{
    if (first != last)
    {
        *destination = *first;

        while (++first != last)
        {
            if (!pred(*destination, *first)) { *++destination = *first; }
        }

        ++destination;
    }

    return destination;
}

/**
 * @brief Copies the elements from the range [first, last), to another range beginning
 * at d_first in such a way that there are no consecutive equal elements. Only the
 * first element of each group of equal elements is copied.
 *
 * @details Elements are compared using operator==. The behavior is undefined if it is
 * not an equivalence relation.
 */
template <class InputIter, class OutputIter>
constexpr auto unique_copy(InputIter first, InputIter last, OutputIter destination)
    -> OutputIter
{
    return etl::unique_copy(first, last, destination, etl::equal_to<> {});
}

/**
 * @brief Reorders the elements in the range [first, last) in such a way that all
 * elements for which the predicate p returns true precede the elements for which
 * predicate p returns false. Relative order of the elements is not preserved.
 */
template <typename ForwardIt, typename UnaryPredicate>
constexpr auto partition(ForwardIt first, ForwardIt last, UnaryPredicate p) -> ForwardIt
{
    first = find_if_not(first, last, p);
    if (first == last) { return first; }

    for (ForwardIt i = next(first); i != last; ++i)
    {
        if (p(*i))
        {
            iter_swap(i, first);
            ++first;
        }
    }
    return first;
}

/**
 * @brief  Reorders the elements in the range [first, last) in such a way
 * that all elements for which the predicate p returns true precede the
 * elements for which predicate p returns false. Relative order of the
 * elements is preserved.
 */
template <typename BidirIt, typename UnaryPredicate>
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
 * proceeding to last - 1. The behavior is undefined if destination is within the
 * range [first, last). In this case, etl::copy_backward may be used instead.
 *
 * @return Output iterator to the element in the destination range, one past the last
 * element copied.
 */
template <typename InputIt, typename OutputIt>
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
 * relative order of the elements that are copied is preserved. The behavior is
 * undefined if the source and the destination ranges overlap.
 *
 * @return Output iterator to the element in the destination range, one past the last
 * element copied.
 */
template <typename InputIt, typename OutputIt, typename UnaryPredicate>
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
 * beginning at result. Formally, for each integer 0 ≤ i < count, performs *(result +
 * i) =
 * *(first + i). Overlap of ranges is formally permitted, but leads to unpredictable
 * ordering of the results.
 *
 * @return Iterator in the destination range, pointing past the last element copied if
 * count>0 or result otherwise.
 */
template <typename InputIt, typename Size, typename OutputIt>
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
 * @brief Copies the elements from the range, defined by [first, last), to another
 * range ending at d_last. The elements are copied in reverse order (the last element
 * is copied first), but their relative order is preserved.
 *
 * @details The behavior is undefined if d_last is within (first, last]. etl::copy
 * must be used instead of etl::copy_backward in that case.
 *
 * @return Iterator to the last element copied.
 */
template <typename BidirIt1, typename BidirIt2>
constexpr auto copy_backward(BidirIt1 first, BidirIt1 last, BidirIt2 d_last) -> BidirIt2
{
    while (first != last) { *(--d_last) = *(--last); }
    return d_last;
}

/**
 * @brief Assigns the given value to the elements in the range [first, last).
 */
template <typename ForwardIt, typename T>
constexpr auto fill(ForwardIt first, ForwardIt last, T const& value) -> void
{
    for (; first != last; ++first) { *first = value; }
}

/**
 * @brief Returns true if the range [first1, last1) is equal to the range [first2,
 * first2
 * + (last1 - first1)), and false otherwise.
 */
template <typename InputIt1, typename InputIt2, typename BinaryPredicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                   BinaryPredicate p) -> bool
{
    for (; first1 != last1; ++first1, ++first2)
    {
        if (!p(*first1, *first2)) { return false; }
    }
    return true;
}

/**
 * @brief Returns true if the range [first1, last1) is equal to the range [first2,
 * first2
 * + (last1 - first1)), and false otherwise.
 */
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2)
    -> bool
{
    return equal(first1, last1, first2, equal_to<> {});
}

/**
 * @brief Returns true if the range [first1, last1) is equal to the range [first2,
 * last2), and false otherwise.
 */
template <typename InputIt1, typename InputIt2, typename BinaryPredicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                   InputIt2 last2, BinaryPredicate p) -> bool
{
    if (etl::distance(first1, last1) != etl::distance(first2, last2)) { return false; }
    return etl::equal(first1, last1, first2, p);
}

/**
 * @brief Returns true if the range [first1, last1) is equal to the range [first2,
 * last2), and false otherwise.
 */
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                   InputIt2 last2) -> bool
{
    return etl::equal(first1, last1, first2, last2, equal_to<> {});
}

/**
 * @brief Checks if the first range [first1, last1) is lexicographically
 * less than the second range [first2, last2). Elements are compared using
 * the given binary comparison function comp.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare
 */
template <typename InputIt1, typename InputIt2, typename Compare>
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
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 first1, InputIt1 last1,
                                                     InputIt2 first2, InputIt2 last2)
    -> bool
{
    return lexicographical_compare(first1, last1, first2, last2,
                                   etl::less<decltype(*first1)> {});
}

/**
 * @brief Sorts the elements in the range [first, last) in non-descending order. The
 * order of equal elements is not guaranteed to be preserved.
 *
 * @details A sequence is sorted with respect to a comparator comp if for any iterator
 * it pointing to the sequence and any non-negative integer n such that it + n is a
 * valid iterator pointing to an element of the sequence, comp(*(it + n), *it) (or
 * *(it + n) < *it) evaluates to false. Bubble sort implementation.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/sort
 */
template <typename RandomIt, typename Compare>
constexpr auto sort(RandomIt first, RandomIt last, Compare comp) -> void
{
    for (auto i = first; i != last; ++i)
    {
        for (auto j = first; j < i; ++j)
        {
            if (comp(*i, *j)) { etl::iter_swap(i, j); }
        }
    }
}

/**
 * @brief Sorts the elements in the range [first, last) in non-descending order. The
 * order of equal elements is not guaranteed to be preserved. Elements are compared
 * using operator<.
 *
 * @details A sequence is sorted with respect to a comparator comp if for any iterator
 * it pointing to the sequence and any non-negative integer n such that it + n is a
 * valid iterator pointing to an element of the sequence, comp(*(it + n), *it) (or
 * *(it + n) < *it) evaluates to false. Bubble sort implementation.
 *
 * @ref https://en.cppreference.com/w/cpp/algorithm/sort
 */
template <typename RandomIt>
constexpr auto sort(RandomIt first, RandomIt last) -> void
{
    sort(first, last, etl::less<> {});
}

/**
 * @brief Examines the range [first, last) and finds the largest range beginning at
 * first in which the elements are sorted in non-descending order. Elements are
 * compared using operator<.
 */
template <typename ForwardIter>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIter first, ForwardIter last)
    -> ForwardIter
{
    return is_sorted_until(first, last, etl::less<>());
}

/**
 * @brief Examines the range [first, last) and finds the largest range beginning at
 * first in which the elements are sorted in non-descending order. Elements are
 * compared using the given binary comparison function comp.
 */
template <typename ForwardIter, typename Compare>
[[nodiscard]] constexpr auto is_sorted_until(ForwardIter first, ForwardIter last,
                                             Compare comp) -> ForwardIter
{
    if (first != last)
    {
        ForwardIter next = first;
        while (++next != last)
        {
            if (comp(*next, *first)) { return next; }
            first = next;
        }
    }
    return last;
}

/**
 * @brief Checks if the elements in range [first, last) are sorted in non-descending
 * order. Elements are compared using operator<.
 */
template <typename ForwardIter>
[[nodiscard]] constexpr auto is_sorted(ForwardIter first, ForwardIter last) -> bool
{
    return etl::is_sorted_until(first, last) == last;
}

/**
 * @brief Checks if the elements in range [first, last) are sorted in non-descending
 * order. Elements are compared using the given binary comparison function comp.
 */
template <typename ForwardIter, typename Compare>
[[nodiscard]] constexpr auto is_sorted(ForwardIter first, ForwardIter last, Compare comp)
    -> bool
{
    return etl::is_sorted_until(first, last, comp) == last;
}

/**
 * @brief Returns true if the sorted range [first2, last2) is a subsequence of the
 * sorted range [first1, last1). Both ranges must be sorted with operator<.
 */
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                      InputIt2 last2) -> bool
{
    for (; first2 != last2; ++first1)
    {
        if (first1 == last1 || *first2 < *first1) { return false; }
        if (!(*first1 < *first2)) { ++first2; }
    }
    return true;
}

/**
 * @brief Returns true if the sorted range [first2, last2) is a subsequence of the
 * sorted range [first1, last1). Both ranges must be sorted with the given comparison
 * function comp.
 */
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                      InputIt2 last2, Compare comp) -> bool
{
    for (; first2 != last2; ++first1)
    {
        if (first1 == last1 || comp(*first2, *first1)) { return false; }
        if (!comp(*first1, *first2)) { ++first2; }
    }
    return true;
}

}  // namespace etl

#endif  // TAETL_ALGORITHM_HPP