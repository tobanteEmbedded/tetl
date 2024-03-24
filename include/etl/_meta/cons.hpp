// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_CONS_HPP
#define TETL_META_CONS_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

namespace detail {

template <typename T, typename List>
struct cons;

template <typename T, typename... Ts>
struct cons<T, list<Ts...>> {
    using type = list<T, Ts...>;
};

} // namespace detail

template <typename T, typename List>
using cons = typename detail::cons<T, List>::type;

} // namespace etl::meta

#endif // TETL_META_CONS_HPP
