// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_STANDARD_SIGNED_INTEGER_HPP
#define TETL_TYPE_TRAITS_IS_STANDARD_SIGNED_INTEGER_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_any_of.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

template <typename T>
inline constexpr auto is_standard_signed_integer_v
    = etl::is_any_of_v<etl::remove_cv_t<T>, signed char, short, int, long, long long>;

template <typename T>
struct is_standard_signed_integer : etl::bool_constant<is_standard_signed_integer_v<T> > { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_STANDARD_SIGNED_INTEGER_HPP