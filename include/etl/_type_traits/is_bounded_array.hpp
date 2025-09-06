// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_BOUNDED_ARRAY_HPP
#define TETL_TYPE_TRAITS_IS_BOUNDED_ARRAY_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Checks whether T is an array type of known bound. Provides the member
/// constant value which is equal to true, if T is an array type of known bound.
/// Otherwise, value is equal to false.
template <typename T>
struct is_bounded_array : false_type { };

template <typename T, size_t N>
struct is_bounded_array<T[N]> : true_type { };

template <typename T>
inline constexpr bool is_bounded_array_v = is_bounded_array<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BOUNDED_ARRAY_HPP
