// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_SYSTEM_ERROR_IS_ERROR_CONDITION_ENUM_HPP
#define TETL_SYSTEM_ERROR_IS_ERROR_CONDITION_ENUM_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct is_error_condition_enum : false_type { };

template <typename T>
inline constexpr auto is_error_condition_enum_v = is_error_condition_enum<T>::value;

} // namespace etl

#endif // TETL_SYSTEM_ERROR_IS_ERROR_CONDITION_ENUM_HPP
