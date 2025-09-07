// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_NULL_POINTER_HPP
#define TETL_TYPE_TRAITS_IS_NULL_POINTER_HPP

#include <etl/_cstddef/nullptr_t.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

template <typename T>
struct is_null_pointer : is_same<nullptr_t, remove_cv_t<T>> { };

template <typename T>
inline constexpr bool is_null_pointer_v = is_null_pointer<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NULL_POINTER_HPP
