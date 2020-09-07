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

#ifndef TAETL_SPAN_HPP
#define TAETL_SPAN_HPP

#include "etl/definitions.hpp"
#include "etl/warning.hpp"

namespace etl
{
/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns exactly c.begin(), which is typically an iterator to the beginning of
 * the sequence represented by c. If C is a standard Container, this returns
 * C::iterator when c is not const-qualified, and C::const_iterator otherwise.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
    return c.begin();
}

/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns exactly c.begin(), which is typically an iterator to the beginning of
 * the sequence represented by c. If C is a standard Container, this returns
 * C::iterator when c is not const-qualified, and C::const_iterator otherwise.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto begin(const C& c) -> decltype(c.begin())
{
    return c.begin();
}

/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns a pointer to the beginning of the array.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class T, etl::size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

/**
 * @brief Returns an iterator to the beginning of the given container c or
 * array array. These templates rely on C::begin() having a reasonable
 * implementation. Returns exactly etl::begin(c), with c always treated as
 * const-qualified. If C is a standard Container, this always returns
 * C::const_iterator.
 *
 * @details Custom overloads of begin may be provided for classes that do
 * not expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto cbegin(const C& c) noexcept(noexcept(etl::begin(c)))
    -> decltype(etl::begin(c))
{
    return etl::begin(c);
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto end(C& c) -> decltype(c.end())
{
    return c.end();
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto end(const C& c) -> decltype(c.end())
{
    return c.end();
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class T, etl::size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
    return &array[N];
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto cend(const C& c) noexcept(noexcept(etl::end(c)))
    -> decltype(etl::end(c))
{
    return etl::end(c);
}

/**
 * @brief Returns the size of the given container c or array array. Returns
 * c.size(), converted to the return type if necessary.
 */
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size()))
    -> decltype(c.size())
{
    return c.size();
}

/**
 * @brief Returns the size of the given container c or array array. Returns N.
 */
template <class T, etl::size_t N>
constexpr auto size(const T (&array)[N]) noexcept -> etl::size_t
{
    etl::ignore_unused(&array[0]);
    return N;
}

/**
 * @brief Returns whether the given container is empty.
 */
template <typename C>
constexpr auto empty(const C& c) noexcept(noexcept(c.empty()))
    -> decltype(c.empty())
{
    return c.empty();
}

/**
 * @brief Returns whether the given container is empty.
 */
template <typename T, etl::size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
    etl::ignore_unused(&array);
    return false;
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns c.data().
 */
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns c.data().
 */
template <typename C>
constexpr auto data(const C& c) noexcept(noexcept(c.data()))
    -> decltype(c.data())
{
    return c.data();
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns &array[0].
 */
template <typename T, etl::size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

}  // namespace etl

#endif  // TAETL_SPAN_HPP
