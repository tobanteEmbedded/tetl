// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ITERATOR_PREV_HPP
#define TETL_ITERATOR_PREV_HPP

#include <etl/_iterator/advance.hpp>
#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// Return the nth predecessor of iterator it.
/// \ingroup iterator
template <typename BidirIt>
[[nodiscard]] constexpr auto prev(BidirIt it, typename iterator_traits<BidirIt>::difference_type n = 1) -> BidirIt
{
    etl::advance(it, -n);
    return it;
}
} // namespace etl

#endif // TETL_ITERATOR_PREV_HPP
