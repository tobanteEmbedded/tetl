// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_OBJECT_HPP
#define TETL_TYPE_TRAITS_IS_OBJECT_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_array.hpp>
#include <etl/_type_traits/is_class.hpp>
#include <etl/_type_traits/is_scalar.hpp>
#include <etl/_type_traits/is_union.hpp>

namespace etl {

/// \brief If T is an object type (that is any possibly cv-qualified type other
/// than function, reference, or void types), provides the member constant value
/// equal true. For any other type, value is false.
template <typename T>
struct is_object;

#if __has_builtin(__is_object)
template <typename T>
struct is_object : bool_constant<__is_object(T)> { };

template <typename T>
inline constexpr bool is_object_v = __is_object(T);

#else

template <typename T>
struct is_object : bool_constant<is_scalar_v<T> || is_array_v<T> || is_union_v<T> || is_class_v<T> > { };

template <typename T>
inline constexpr bool is_object_v = is_object<T>::value;

#endif
} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_OBJECT_HPP
