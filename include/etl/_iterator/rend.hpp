// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_REND_HPP
#define TETL_ITERATOR_REND_HPP

#include <etl/_iterator/begin.hpp>

namespace etl {

template <typename Iter>
struct reverse_iterator;

/// \brief Returns an iterator to the reverse-end of the given container.
template <typename Container>
constexpr auto rend(Container& c) -> decltype(c.rend())
{
    return c.rend();
}

template <typename Container>
constexpr auto rend(Container const& c) -> decltype(c.rend())
{
    return c.rend();
}

template <typename T, size_t N>
constexpr auto rend(T (&array)[N]) -> reverse_iterator<T*>
{
    return reverse_iterator<T*>(begin(array));
}

/// \brief Returns an iterator to the reverse-end of the given container.
template <typename Container>
constexpr auto crend(Container const& c) -> decltype(rend(c))
{
    return rend(c);
}

} // namespace etl

#endif // TETL_ITERATOR_REND_HPP
