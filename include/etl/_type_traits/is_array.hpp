// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_ARRAY_HPP
#define TETL_TYPE_TRAITS_IS_ARRAY_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Checks whether T is an array type. Provides the member constant value
/// which is equal to true, if T is an array type. Otherwise, value is equal to
/// false.
/// \details The behavior of a program that adds specializations for is_array or
/// is_array_v is undefined.
template <typename T>
struct is_array : false_type { };

template <typename T>
struct is_array<T[]> : true_type { };

template <typename T, size_t N>
struct is_array<T[N]> : true_type { };

template <typename T>
inline constexpr bool is_array_v = is_array<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ARRAY_HPP
