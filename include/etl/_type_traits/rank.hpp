/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_RANK_HPP
#define TETL_TYPE_TRAITS_RANK_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

/// \brief If Type is an array type, provides the member constant value equal to
/// the number of dimensions of the array. For any other type, value is 0. The
/// behavior of a program that adds specializations for rank or rank_v is
/// undefined.
template <typename T>
struct rank : integral_constant<size_t, 0> { };

template <typename T>
struct rank<T[]> : integral_constant<size_t, rank<T>::value + 1> { };

template <typename T, size_t N>
struct rank<T[N]> : integral_constant<size_t, rank<T>::value + 1> { };

template <typename Type>
inline constexpr size_t rank_v = rank<Type>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_RANK_HPP
