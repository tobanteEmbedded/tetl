// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_SAME_HPP
#define TETL_TYPE_TRAITS_IS_SAME_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T, typename U>
inline constexpr bool is_same_v = false;

template <typename T>
inline constexpr bool is_same_v<T, T> = true;

/// \brief If T and U name the same type (taking into account const/volatile
/// qualifications), provides the member constant value equal to true. Otherwise
/// value is false.
template <typename T, typename U>
struct is_same : bool_constant<is_same_v<T, U>> { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SAME_HPP
