// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_CLASS_HPP
#define TETL_TYPE_TRAITS_IS_CLASS_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct is_class : bool_constant<__is_class(T)> { };

template <typename T>
inline constexpr bool is_class_v = __is_class(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CLASS_HPP
