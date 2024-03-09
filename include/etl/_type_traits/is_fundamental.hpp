// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_FUNDAMENTAL_HPP
#define TETL_TYPE_TRAITS_IS_FUNDAMENTAL_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/is_null_pointer.hpp>
#include <etl/_type_traits/is_void.hpp>

namespace etl {

/// \brief If T is a fundamental type (that is, arithmetic type, void, or
/// nullptr_t), provides the member constant value equal true. For any other
/// type, value is false.
template <typename T>
struct is_fundamental : bool_constant<is_arithmetic_v<T> || is_void_v<T> || is_null_pointer_v<T>> { };

template <typename T>
inline constexpr bool is_fundamental_v = is_fundamental<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_FUNDAMENTAL_HPP
