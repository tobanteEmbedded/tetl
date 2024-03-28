// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP
#define TETL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_function.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

#if defined(TETL_COMPILER_CLANG)

template <typename T>
inline constexpr bool is_member_function_pointer_v = __is_member_function_pointer(T);

template <typename T>
struct is_member_function_pointer : bool_constant<__is_member_function_pointer(T)> { };

#else

namespace detail {
template <typename T>
struct is_member_function_pointer_helper : etl::false_type { };

template <typename T, typename U>
struct is_member_function_pointer_helper<T U::*> : etl::is_function<T> { };

} // namespace detail

/// \brief Checks whether T is a non-static member function pointer. Provides
/// the member constant value which is equal to true, if T is a non-static
/// member function pointer type. Otherwise, value is equal to false.
template <typename T>
struct is_member_function_pointer : detail::is_member_function_pointer_helper<remove_cv_t<T> > { };

template <typename T>
inline constexpr bool is_member_function_pointer_v = is_member_function_pointer<T>::value;

#endif

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP
