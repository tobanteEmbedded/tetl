// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_MEMBER_OBJECT_POINTER_HPP
#define TETL_TYPE_TRAITS_IS_MEMBER_OBJECT_POINTER_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_member_function_pointer.hpp>
#include <etl/_type_traits/is_member_pointer.hpp>

namespace etl {

#if defined(TETL_COMPILER_CLANG)

template <typename T>
inline constexpr bool is_member_object_pointer_v = __is_member_object_pointer(T);

template <typename T>
struct is_member_object_pointer : bool_constant<__is_member_object_pointer(T)> { };

#else

/// \brief Checks whether T is a non-static member object pointer. Provides the
/// member constant value which is equal to true, if T is a non-static member
/// object pointer type. Otherwise, value is equal to false.
template <typename T>
struct is_member_object_pointer : bool_constant<is_member_pointer_v<T> && !is_member_function_pointer_v<T> > { };

template <typename T>
inline constexpr bool is_member_object_pointer_v = is_member_object_pointer<T>::value;

#endif

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_MEMBER_OBJECT_POINTER_HPP
