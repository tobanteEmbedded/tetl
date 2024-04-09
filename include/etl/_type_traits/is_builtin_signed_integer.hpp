// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP

#include <etl/_meta/contains.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

/// \relates is_builtin_signed_integer
template <typename T>
inline constexpr auto is_builtin_signed_integer_v
    = meta::contains_v<remove_cv_t<T>, meta::list<signed char, short, int, long, long long>>;

template <typename T>
struct is_builtin_signed_integer : bool_constant<is_builtin_signed_integer_v<T>> { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BUILTIN_SIGNED_INTEGER_HPP
