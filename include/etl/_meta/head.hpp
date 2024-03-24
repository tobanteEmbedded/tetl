// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_HEAD_HPP
#define TETL_META_HEAD_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

template <typename... Ts>
struct head;

template <typename T, typename... Ts>
struct head<list<T, Ts...>> {
    using type = T;
};

template <typename List>
using head_t = typename head<List>::type;

} // namespace etl::meta

#endif // TETL_META_HEAD_HPP
