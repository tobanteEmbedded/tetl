// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_AT_HPP
#define TETL_META_AT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_meta/list.hpp>

namespace etl::meta {

template <etl::size_t I, typename List>
struct at;

template <typename Head, typename... Tail>
struct at<0, list<Head, Tail...>> {
    using type = Head;
};

template <etl::size_t I, typename Head, typename... Tail>
struct at<I, list<Head, Tail...>> {
    using type = typename at<I - 1, list<Tail...>>::type;
};

template <etl::size_t I, typename List>
using at_t = typename at<I, List>::type;

} // namespace etl::meta

#endif // TETL_META_AT_HPP
