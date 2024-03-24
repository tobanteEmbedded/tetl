// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_AT_HPP
#define TETL_META_AT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_meta/list.hpp>

namespace etl::meta {

template <etl::size_t I, typename List>
struct at;

template <typename T, typename... Ts>
struct at<0, list<T, Ts...>> {
    using type = T;
};

template <etl::size_t I, typename T, typename... Ts>
struct at<I, list<T, Ts...>> {
    using type = typename at<I - 1, list<Ts...>>::type;
};

template <etl::size_t I, typename List>
using at_t = typename at<I, List>::type;

} // namespace etl::meta

#endif // TETL_META_AT_HPP
