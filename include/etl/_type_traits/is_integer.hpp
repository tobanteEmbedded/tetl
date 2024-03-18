// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_INTEGER_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_signed_integer.hpp>
#include <etl/_type_traits/is_unsigned_integer.hpp>

namespace etl {

template <typename T>
inline constexpr auto is_integer_v = is_unsigned_integer_v<T> or is_signed_integer_v<T>;

template <typename T>
struct is_integer : bool_constant<is_integer_v<T> > { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_INTEGER_HPP
