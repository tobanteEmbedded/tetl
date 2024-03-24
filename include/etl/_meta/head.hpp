// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_HEAD_HPP
#define TETL_META_HEAD_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

template <typename... Ts>
struct head;

template <typename Head, typename... Tail>
struct head<list<Head, Tail...>> {
    using type = Head;
};

template <typename List>
using head_t = typename head<List>::type;

} // namespace etl::meta

#endif // TETL_META_HEAD_HPP
