// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SCALAR_HPP
#define TETL_TYPE_TRAITS_IS_SCALAR_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/is_enum.hpp>
#include <etl/_type_traits/is_member_pointer.hpp>
#include <etl/_type_traits/is_null_pointer.hpp>
#include <etl/_type_traits/is_pointer.hpp>

namespace etl {

/// \brief If T is a scalar type (that is a possibly cv-qualified arithmetic,
/// pointer, pointer to member, enumeration, or etl::nullptr_t type), provides
/// the member constant value equal true. For any other type, value is false.
template <typename T>
struct is_scalar;

#if __has_builtin(__is_scalar)

template <typename T>
struct is_scalar : bool_constant<__is_scalar(T)> { };

template <typename T>

inline constexpr bool is_scalar_v = __is_scalar(T);
#else

template <typename T>
struct is_scalar
    : bool_constant<
          is_arithmetic_v<T> or is_enum_v<T> or is_pointer_v<T> or is_member_pointer_v<T> or is_null_pointer_v<T>
      > { };

template <typename T>

inline constexpr bool is_scalar_v = is_scalar<T>::value;

#endif

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SCALAR_HPP
