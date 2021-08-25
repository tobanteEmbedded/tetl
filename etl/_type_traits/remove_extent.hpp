/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_EXTENT_HPP
#define TETL_TYPE_TRAITS_REMOVE_EXTENT_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief If T is an array of some type X, provides the member typedef type
/// equal to X, otherwise type is T. Note that if T is a multidimensional array,
/// only the first dimension is removed. The behavior of a program that adds
/// specializations for remove_extent is undefined.
/// \group remove_extent
template <typename T>
struct remove_extent {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_extent<T[]> {
    using type = T;
};

/// \exclude
template <typename T, etl::size_t N>
struct remove_extent<T[N]> {
    using type = T;
};

/// \group remove_extent
template <typename T>
using remove_extent_t = typename etl::remove_extent<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_EXTENT_HPP