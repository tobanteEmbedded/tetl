// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP
#define TETL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/is_enum.hpp"
#include "etl/_type_traits/underlying_type.hpp"

namespace etl {

template <typename T, bool = is_enum_v<T>>
struct is_scoped_enum : false_type { };

template <typename T>
struct is_scoped_enum<T, true> : bool_constant<!is_convertible_v<T, underlying_type_t<T>>> { };

/// \brief Checks whether T is an scoped enumeration type. Provides the member
/// constant value which is equal to true, if T is an scoped enumeration type.
/// Otherwise, value is equal to false. The behavior of a program that adds
/// specializations for is_scoped_enum or is_scoped_enum_v is undefined.
///
/// https://en.cppreference.com/w/cpp/types/is_scoped_enum
template <typename T>
inline constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP
