// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_ITERATOR_END_HPP
#define TETL_ITERATOR_END_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// \ingroup iterator
template <typename C>
constexpr auto end(C& c) -> decltype(c.end())
{
    return c.end();
}

/// \ingroup iterator
template <typename C>
constexpr auto end(C const& c) -> decltype(c.end())
{
    return c.end();
}

/// \ingroup iterator
template <typename T, etl::size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
    return &array[N];
}

/// \ingroup iterator
template <typename C>
constexpr auto cend(C const& c) noexcept(noexcept(end(c))) -> decltype(end(c))
{
    return end(c);
}

} // namespace etl

#endif // TETL_ITERATOR_END_HPP
