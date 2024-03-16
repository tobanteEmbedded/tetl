// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_REFERENCE_HPP
#define TETL_TYPE_TRAITS_IS_REFERENCE_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief If T is a reference type (lvalue reference or rvalue reference),
/// provides the member constant value equal true. For any other type, value is
/// false. The behavior of a program that adds specializations for is_reference
/// or is_reference_v is undefined.
template <typename T>
struct is_reference : false_type { };

/// \exclude
template <typename T>
struct is_reference<T&> : true_type { };

/// \exclude
template <typename T>
struct is_reference<T&&> : true_type { };

template <typename T>
inline constexpr bool is_reference_v = is_reference<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_REFERENCE_HPP
