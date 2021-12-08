/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_EMPTY_HPP
#define TETL_ITERATOR_EMPTY_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Returns whether the given container is empty.
/// \group empty
/// \module Iterator
template <typename C>
constexpr auto empty(C const& c) noexcept(noexcept(c.empty())) -> decltype(c.empty())
{
    return c.empty();
}

/// \group empty
template <typename T, size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
    etl::ignore_unused(&array);
    return false;
}

} // namespace etl

#endif // TETL_ITERATOR_EMPTY_HPP