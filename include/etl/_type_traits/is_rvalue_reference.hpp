// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_RVALUE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_IS_RVALUE_REFERENCE_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Checks whether T is a rvalue reference type. Provides the member
/// constant value which is equal to true, if T is a rvalue reference type.
/// Otherwise, value is equal to false.
template <typename T>
struct is_rvalue_reference : false_type { };

/// \exclude
template <typename T>
struct is_rvalue_reference<T&&> : true_type { };

template <typename T>
inline constexpr bool is_rvalue_reference_v = is_rvalue_reference<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_RVALUE_REFERENCE_HPP
