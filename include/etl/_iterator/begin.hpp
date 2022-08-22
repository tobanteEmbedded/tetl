/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_BEGIN_HPP
#define TETL_ITERATOR_BEGIN_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on `C::begin()` having a reasonable
/// implementation. Returns exactly c.begin(), which is typically an iterator to
/// the beginning of the sequence represented by c. If C is a standard
/// Container, this returns `C::iterator` when c is not const-qualified, and
/// `C::const_iterator` otherwise. Custom overloads of begin may be provided for
/// classes that do not expose a suitable begin() member function, yet can be
/// iterated.
template <typename C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
    return c.begin();
}

template <typename C>
constexpr auto begin(C const& c) -> decltype(c.begin())
{
    return c.begin();
}

template <typename T, etl::size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

template <typename C>
constexpr auto cbegin(C const& c) noexcept(noexcept(begin(c))) -> decltype(begin(c))
{
    return begin(c);
}

} // namespace etl

#endif // TETL_ITERATOR_BEGIN_HPP
