// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_CONST_HPP
#define TETL_TYPE_TRAITS_IS_CONST_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief If T is a const-qualified type (that is, const, or const volatile),
/// provides the member constant value equal to true. For any other type, value
/// is false.
template <typename T>
struct is_const : false_type { };

template <typename T>
struct is_const<T const> : true_type { };

template <typename T>
inline constexpr bool is_const_v = is_const<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONST_HPP
