// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_CONS_HPP
#define TETL_META_CONS_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

template <typename T, typename List>
struct cons;

template <typename T, typename... Ts>
struct cons<T, list<Ts...>> {
    using type = list<T, Ts...>;
};

template <typename T, typename List>
using cons_t = typename cons<T, List>::type;

} // namespace etl::meta

#endif // TETL_META_CONS_HPP
