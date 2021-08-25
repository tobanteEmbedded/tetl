/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_LVALUE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_IS_LVALUE_REFERENCE_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief Checks whether T is a lvalue reference type. Provides the member
/// constant value which is equal to true, if T is a lvalue reference type.
/// Otherwise, value is equal to false.
/// \group is_lvalue_reference
template <typename T>
struct is_lvalue_reference : false_type {
};

/// \exclude
template <typename T>
struct is_lvalue_reference<T&> : true_type {
};

/// \group is_lvalue_reference
template <typename T>
inline constexpr bool is_lvalue_reference_v = is_lvalue_reference<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_LVALUE_REFERENCE_HPP