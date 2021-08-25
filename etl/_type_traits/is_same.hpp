/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_SAME_HPP
#define TETL_TYPE_TRAITS_IS_SAME_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If T and U name the same type (taking into account const/volatile
/// qualifications), provides the member constant value equal to true. Otherwise
/// value is false.
/// \group is_same
template <typename T, typename U>
struct is_same : false_type {
};

/// \exclude
template <typename T>
struct is_same<T, T> : true_type {
};

/// \group is_same
template <typename T, typename U>
inline constexpr bool is_same_v = is_same<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SAME_HPP