/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_MEMBER_POINTER_HPP
#define TETL_TYPE_TRAITS_IS_MEMBER_POINTER_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

namespace detail {
template <typename T>
struct is_member_pointer_helper : etl::false_type {
};

template <typename T, typename U>
struct is_member_pointer_helper<T U::*> : etl::true_type {
};
} // namespace detail

/// \brief If T is pointer to non-static member object or a pointer to
/// non-static member function, provides the member constant value equal true.
/// For any other type, value is false. The behavior of a program that adds
/// specializations for is_member_pointer or is_member_pointer_v (since C++17)
/// is undefined.
template <typename T>
struct is_member_pointer : detail::is_member_pointer_helper<remove_cv_t<T>> {
};

template <typename T>
inline constexpr bool is_member_pointer_v = is_member_pointer<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_MEMBER_POINTER_HPP