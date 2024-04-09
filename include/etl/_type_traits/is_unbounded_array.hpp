// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_UNBOUNDED_ARRAY_HPP
#define TETL_TYPE_TRAITS_IS_UNBOUNDED_ARRAY_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Checks whether T is an array type of unknown bound. Provides the
/// member constant value which is equal to true, if T is an array type of
/// unknown bound. Otherwise, value is equal to false.
template <typename T>
struct is_unbounded_array : false_type { };

template <typename T>
struct is_unbounded_array<T[]> : true_type { };

template <typename T>
inline constexpr bool is_unbounded_array_v = is_unbounded_array<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNBOUNDED_ARRAY_HPP
