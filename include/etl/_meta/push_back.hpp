// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_PUSH_BACK_HPP
#define TETL_META_PUSH_BACK_HPP

#include <etl/_meta/list.hpp>

namespace etl::meta {

namespace detail {

template <typename T, typename List>
struct push_back;

template <typename T, typename... Ts>
struct push_back<T, list<Ts...>> {
    using type = list<Ts..., T>;
};

} // namespace detail

template <typename T, typename List>
using push_back = typename detail::push_back<T, List>::type;

} // namespace etl::meta

#endif // TETL_META_PUSH_BACK_HPP
