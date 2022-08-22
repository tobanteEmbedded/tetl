/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TUPLE_TUPLE_SIZE_HPP
#define TETL_TUPLE_TUPLE_SIZE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

template <typename... Ts>
struct tuple;

template <typename T>
struct tuple_size; /*undefined*/

template <typename T>
struct tuple_size<T const> : integral_constant<size_t, tuple_size<T>::value> {
};

template <typename T>
struct tuple_size<T volatile> : integral_constant<size_t, tuple_size<T>::value> {
};

template <typename T>
struct tuple_size<T const volatile> : integral_constant<size_t, tuple_size<T>::value> {
};

template <typename T>
inline constexpr auto tuple_size_v = tuple_size<T>::value;

} // namespace etl

#endif // TETL_TUPLE_TUPLE_SIZE_HPP
