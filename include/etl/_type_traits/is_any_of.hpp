// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_ANY_OF_HPP
#define TETL_TYPE_TRAITS_IS_ANY_OF_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/disjunction.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

template <typename T, typename... Types>
inline constexpr bool is_any_of_v = disjunction_v<is_same<T, Types>...>;

template <typename T, typename... Types>
struct is_any_of : bool_constant<is_any_of_v<T, Types...>> { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ANY_OF_HPP
