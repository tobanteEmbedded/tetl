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
constexpr auto for_each_n(InputIt first, Size n, UnaryFunction f) noexcept
    -> InputIt
{
    for (Size i = 0; i < n; ++first, (void)++i) { f(*first); }
    return first;
}

/**
 * @brief Searches for an element equal to value.
 */
template <class InputIt, class T>
[[nodiscard]] constexpr auto find(InputIt first, InputIt last,
                                  const T& value) noexcept -> InputIt
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
[[nodiscard]] constexpr auto max(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (a < b) ? b : a;
}

/**
 * @brief Returns the greater of a and b, using a compare function.
 */
template <class Type, class Compare>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b,
                                 Compare comp) noexcept -> Type const&
{
    return (comp(a, b)) ? b : a;
}

/**
 * @brief Finds the greatest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <class ForwardIterator>
[[nodiscard]] constexpr auto max_element(ForwardIterator first,
                                         ForwardIterator last) noexcept
    -> ForwardIterator
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
[[nodiscard]] constexpr auto max_element(ForwardIterator first,
                                         ForwardIterator last, Compare comp)
    -> ForwardIterator
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
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (b < a) ? b : a;
}

/**
 * @brief Returns the smaller of a and b, using a compare function.
 */
template <class Type, class Compare>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b,
                                 Compare comp) noexcept -> Type const&
{
    return (comp(b, a)) ? b : a;
}

/**
 * @brief Finds the smallest element in the range [first, last). Elements are
 * compared using operator<.
 */
template <class ForwardIterator>
[[nodiscard]] constexpr auto min_element(ForwardIterator first,
                                         ForwardIterator last) noexcept
    -> ForwardIterator
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
[[nodiscard]] constexpr auto min_element(ForwardIterator first,
                                         ForwardIterator last, Compare comp)
    -> ForwardIterator
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
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo,
                                   Type const& hi) noexcept -> Type const&
{
    return clamp(v, lo, hi, etl::less<Type>());
}

template <class Type, class Compare>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo,
                                   Type const& hi, Compare comp) -> Type const&
{
    ETL_ASSERT(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

/**
 * @brief Checks if unary predicate p returns true for all elements in the range
 * [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto all_of(InputIt first, InputIt last,
                                    UnaryPredicate p) -> bool
{
    return etl::find_if_not(first, last, p) == last;
}

/**
 * @brief Checks if unary predicate p returns true for at least one element in
 * the range [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto any_of(InputIt first, InputIt last,
                                    UnaryPredicate p) -> bool
{
    return etl::find_if(first, last, p) != last;
}

/**
 * @brief Checks if unary predicate p returns true for no elements in the range
 * [first, last).
 */
template <class InputIt, class UnaryPredicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last,
                                     UnaryPredicate p) -> bool
{
    return etl::find_if(first, last, p) == last;
}
}  // namespace etl

#endif  // TAETL_ALGORITHM_HPP