// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_RBEGIN_HPP
#define TETL_ITERATOR_RBEGIN_HPP

#include "etl/_iterator/end.hpp"

namespace etl {

template <typename Iter>
struct reverse_iterator;

/// \brief Returns an iterator to the reverse-beginning of the given container.
template <typename Container>
constexpr auto rbegin(Container& c) -> decltype(c.rbegin())
{
    return c.rbegin();
}

template <typename Container>
constexpr auto rbegin(Container const& c) -> decltype(c.rbegin())
{
    return c.rbegin();
}

template <typename T, size_t N>
constexpr auto rbegin(T (&array)[N]) -> reverse_iterator<T*>
{
    return reverse_iterator<T*>(end(array));
}

template <typename Container>
constexpr auto crbegin(Container const& c) -> decltype(rbegin(c))
{
    return rbegin(c);
}

} // namespace etl

#endif // TETL_ITERATOR_RBEGIN_HPP
