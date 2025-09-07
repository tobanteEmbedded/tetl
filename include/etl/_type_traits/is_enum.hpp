// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_ENUM_HPP
#define TETL_TYPE_TRAITS_IS_ENUM_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct is_enum : bool_constant<__is_enum(T)> { };

template <typename T>
inline constexpr bool is_enum_v = __is_enum(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ENUM_HPP
