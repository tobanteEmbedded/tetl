/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_REND_HPP
#define TETL_ITERATOR_REND_HPP

#include "etl/_iterator/begin.hpp"

namespace etl {

template <typename Iter>
struct reverse_iterator;

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
/// \module Iterator
template <typename Container>
constexpr auto rend(Container& c) -> decltype(c.rend())
{
    return c.rend();
}

/// \group rend
template <typename Container>
constexpr auto rend(Container const& c) -> decltype(c.rend())
{
    return c.rend();
}

/// \group rend
template <typename T, size_t N>
constexpr auto rend(T (&array)[N]) -> reverse_iterator<T*>
{
    return reverse_iterator<T*>(begin(array));
}

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
template <typename Container>
constexpr auto crend(Container const& c) -> decltype(rend(c))
{
    return rend(c);
}

} // namespace etl

#endif // TETL_ITERATOR_REND_HPP