// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_EMPTY_HPP
#define TETL_ITERATOR_EMPTY_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_utility/ignore_unused.hpp>

namespace etl {

/// Returns whether the given container is empty.
/// \ingroup iterator

template <typename C>
constexpr auto empty(C const& c) noexcept(noexcept(c.empty())) -> decltype(c.empty())
{
    return c.empty();
}

/// Returns whether the given container is empty.
/// \ingroup iterator
template <typename T, size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
    etl::ignore_unused(&array);
    return false;
}

} // namespace etl

#endif // TETL_ITERATOR_EMPTY_HPP
