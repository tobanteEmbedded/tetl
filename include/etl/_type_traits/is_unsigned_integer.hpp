// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_UNSIGNED_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_UNSIGNED_INTEGER_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_any_of.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

template <typename T>
inline constexpr auto is_unsigned_integer_v
    = is_any_of_v<remove_cv_t<T>, unsigned char, unsigned short, unsigned int, unsigned long, unsigned long long>;

template <typename T>
struct is_unsigned_integer : bool_constant<is_unsigned_integer_v<T> > { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNSIGNED_INTEGER_HPP
