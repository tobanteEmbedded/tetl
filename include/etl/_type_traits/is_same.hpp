// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_SAME_HPP
#define TETL_TYPE_TRAITS_IS_SAME_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief If T and U name the same type (taking into account const/volatile
/// qualifications), provides the member constant value equal to true. Otherwise
/// value is false.
/// \ingroup type_traits
template <typename T, typename U>
struct is_same : false_type { };

/// \ingroup type_traits
template <typename T>
struct is_same<T, T> : true_type { };

/// \ingroup type_traits
template <typename T, typename U>
inline constexpr bool is_same_v = is_same<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SAME_HPP
