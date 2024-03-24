// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_PUSH_FRONT_HPP
#define TETL_META_PUSH_FRONT_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

namespace detail {

template <typename T, typename List>
struct push_front;

template <typename T, typename... Ts>
struct push_front<T, list<Ts...>> {
    using type = list<T, Ts...>;
};

} // namespace detail

template <typename T, typename List>
using push_front = typename detail::push_front<T, List>::type;

} // namespace etl::meta

#endif // TETL_META_PUSH_FRONT_HPP
