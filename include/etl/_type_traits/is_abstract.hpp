// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_ABSTRACT_HPP
#define TETL_TYPE_TRAITS_IS_ABSTRACT_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct is_abstract : bool_constant<__is_abstract(T)> { };

template <typename T>
inline constexpr bool is_abstract_v = __is_abstract(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ABSTRACT_HPP
