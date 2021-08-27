/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_TYPE_PACK_ELEMENT_HPP
#define TETL_TYPE_TRAITS_TYPE_PACK_ELEMENT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/integral_constant.hpp"

namespace etl {
namespace detail {
template <etl::size_t I, typename T>
struct type_pack_element_wrapper {
    static auto get_type(etl::integral_constant<etl::size_t, I> /*ic*/) -> T;
};

template <etl::size_t I, typename... Ts>
struct type_pack_element_impl;

template <etl::size_t I, etl::size_t... Is, typename... Ts>
struct type_pack_element_impl<I, etl::index_sequence<Is...>, Ts...>
    : type_pack_element_wrapper<Is, Ts>... {
private:
    using type_pack_element_wrapper<Is, Ts>::get_type...;

public:
    using type = decltype(get_type(
        etl::declval<etl::integral_constant<etl::size_t, I>>()));
};

} // namespace detail

template <etl::size_t I, typename... Ts>
struct type_pack_element {
    using type = typename detail::type_pack_element_impl<I,
        etl::index_sequence_for<Ts...>, Ts...>::type;
};

template <etl::size_t I, typename... Ts>
using type_pack_element_t = typename type_pack_element<I, Ts...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_TYPE_PACK_ELEMENT_HPP