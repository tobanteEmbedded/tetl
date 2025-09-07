// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_BUILTIN_UNSIGNED_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_BUILTIN_UNSIGNED_INTEGER_HPP

#include <etl/_mpl/contains.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

/// True if T is `unsigned char` or `unsigned short` or `unsigned int` or `unsigned long` or `unsigned long long`
template <typename T>
struct is_builtin_unsigned_integer
    : bool_constant<mpl::contains_v<
          remove_cv_t<T>,
          mpl::list<unsigned char, unsigned short, unsigned int, unsigned long, unsigned long long>
      >> { };

/// \relates is_builtin_unsigned_integer
template <typename T>
inline constexpr auto is_builtin_unsigned_integer_v = is_builtin_unsigned_integer<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BUILTIN_UNSIGNED_INTEGER_HPP
