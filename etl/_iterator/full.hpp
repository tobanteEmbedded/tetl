/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_FULL_HPP
#define TETL_ITERATOR_FULL_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Returns whether the given container is full.
/// \group full
/// \module Iterator
template <typename C>
constexpr auto full(C const& c) noexcept(noexcept(c.full()))
    -> decltype(c.full())
{
    return c.full();
}

/// \group full
template <typename T, size_t N>
constexpr auto full(T (&array)[N]) noexcept -> bool
{
    etl::ignore_unused(&array);
    return true;
}

} // namespace etl

#endif // TETL_ITERATOR_FULL_HPP