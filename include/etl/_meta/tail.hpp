// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_TAIL_HPP
#define TETL_META_TAIL_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

namespace detail {

template <typename... Ts>
struct tail;

template <typename T, typename... Ts>
struct tail<list<T, Ts...>> {
    using type = list<Ts...>;
};

} // namespace detail

template <typename List>
using tail = typename detail::tail<List>::type;

} // namespace etl::meta

#endif // TETL_META_TAIL_HPP
