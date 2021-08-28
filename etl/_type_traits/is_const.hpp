/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_CONST_HPP
#define TETL_TYPE_TRAITS_IS_CONST_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If T is a const-qualified type (that is, const, or const volatile),
/// provides the member constant value equal to true. For any other type, value
/// is false.
/// \group is_const
template <typename T>
struct is_const : etl::false_type {
};

/// \exclude
template <typename T>
struct is_const<T const> : etl::true_type {
};

/// \group is_const
template <typename T>
inline constexpr bool is_const_v = etl::is_const<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONST_HPP