// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TUPLE_TUPLE_ELEMENT_HPP
#define TETL_TUPLE_TUPLE_ELEMENT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/add_cv.hpp>
#include <etl/_type_traits/add_volatile.hpp>

namespace etl {

template <typename... Ts>
struct tuple;

template <size_t I, typename T>
struct tuple_element;

template <size_t I, typename T>
using tuple_element_t = typename tuple_element<I, T>::type;

template <size_t I, typename T>
struct tuple_element<I, T const> {
    using type = add_const_t<typename tuple_element<I, T>::type>;
};

template <size_t I, typename T>
struct tuple_element<I, T volatile> {
    using type = add_volatile_t<typename tuple_element<I, T>::type>;
};

template <size_t I, typename T>
struct tuple_element<I, T const volatile> {
    using type = add_cv_t<typename tuple_element<I, T>::type>;
};

} // namespace etl

#endif // TETL_TUPLE_TUPLE_ELEMENT_HPP
