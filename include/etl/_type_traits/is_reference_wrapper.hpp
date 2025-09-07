// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP
#define TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct reference_wrapper;

template <typename T>
struct is_reference_wrapper : false_type { };

template <typename U>
struct is_reference_wrapper<reference_wrapper<U>> : true_type { };

template <typename T>
inline constexpr bool is_reference_wrapper_v = is_reference_wrapper<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP
