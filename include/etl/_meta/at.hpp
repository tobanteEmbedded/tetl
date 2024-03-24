// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_AT_HPP
#define TETL_META_AT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_meta/list.hpp>

namespace etl::meta {

namespace detail {

template <etl::size_t I, typename T, typename... Ts>
struct at_impl {
    using type = typename at_impl<I - 1, Ts...>::type;
};

template <typename T, typename... Ts>
struct at_impl<0, T, Ts...> {
    using type = T;
};

} // namespace detail

template <etl::size_t I, typename List>
struct at;

template <etl::size_t I, typename... Ts>
struct at<I, list<Ts...>> {
    using type = typename detail::at_impl<I, Ts...>::type;
};

template <etl::size_t I, typename List>
using at_t = typename at<I, List>::type;

} // namespace etl::meta

#endif // TETL_META_AT_HPP
