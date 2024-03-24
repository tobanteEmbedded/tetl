// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_TYPE_SEQUENCE_HPP
#define TETL_TYPE_TRAITS_TYPE_SEQUENCE_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

template <typename... Ts>
struct type_sequence { };

template <typename... Ts>
struct head;

template <typename T, typename... Ts>
struct head<type_sequence<T, Ts...>> {
    using type = T;
};

template <typename List>
using head_t = typename head<List>::type;

template <typename... Ts>
struct tail;

template <typename T, typename... Ts>
struct tail<type_sequence<T, Ts...>> {
    using type = type_sequence<Ts...>;
};

template <typename List>
using tail_t = typename tail<List>::type;

template <typename T, typename List>
struct cons;

template <typename T, typename... Ts>
struct cons<T, type_sequence<Ts...>> {
    using type = type_sequence<T, Ts...>;
};

template <typename T, typename List>
using cons_t = typename cons<T, List>::type;

namespace detail {
template <etl::size_t I, typename T, typename... Ts>
struct nth_type {
    using type = typename nth_type<I - 1, Ts...>::type;
};

template <typename T, typename... Ts>
struct nth_type<0, T, Ts...> {
    using type = T;
};
} // namespace detail

template <etl::size_t I, typename List>
struct nth_type;

template <etl::size_t I, typename... Ts>
struct nth_type<I, type_sequence<Ts...>> {
    using type = typename detail::nth_type<I, Ts...>::type;
};

template <etl::size_t I, typename List>
using nth_type_t = typename nth_type<I, List>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_TYPE_SEQUENCE_HPP
