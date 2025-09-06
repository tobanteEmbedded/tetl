// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_POINTER_HPP
#define TETL_TYPE_TRAITS_IS_POINTER_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

namespace detail {
template <typename T>
struct is_pointer : etl::false_type { };

template <typename T>
struct is_pointer<T*> : etl::true_type { };
} // namespace detail

/// \brief Checks whether T is a pointer to object or a pointer to function (but
/// not a pointer to member/member function). Provides the member constant value
/// which is equal to true, if T is a object/function pointer type. Otherwise,
/// value is equal to false.
///
/// \details The behavior of a program that adds specializations for is_pointer
/// or is_pointer_v is undefined.
template <typename T>
struct is_pointer : etl::detail::is_pointer<etl::remove_cv_t<T>> { };

template <typename T>
inline constexpr bool is_pointer_v = is_pointer<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_POINTER_HPP
