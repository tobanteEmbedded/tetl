/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_ALL_EXTENTS_HPP
#define TETL_TYPE_TRAITS_REMOVE_ALL_EXTENTS_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief If T is a multidimensional array of some type X, provides the member
/// typedef type equal to X, otherwise type is T. The behavior of a program that
/// adds specializations for remove_all_extents is undefined.
template <typename T>
struct remove_all_extents {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_all_extents<T[]> {
    using type = typename remove_all_extents<T>::type;
};

/// \exclude
template <typename T, size_t N>
struct remove_all_extents<T[N]> {
    using type = typename remove_all_extents<T>::type;
};

template <typename T>
using remove_all_extents_t = typename remove_all_extents<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_ALL_EXTENTS_HPP
