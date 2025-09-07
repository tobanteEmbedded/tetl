// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP

#include <etl/_mpl/contains.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

template <typename T>
struct is_builtin_signed_integer
    : bool_constant<mpl::contains_v<remove_cv_t<T>, mpl::list<signed char, short, int, long, long long>>> { };

/// \relates is_builtin_signed_integer
template <typename T>
inline constexpr auto is_builtin_signed_integer_v = is_builtin_signed_integer<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP
