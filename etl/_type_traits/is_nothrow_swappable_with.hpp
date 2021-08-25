/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_WITH_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_WITH_HPP

#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_swappable_with.hpp"

namespace etl {

// clang-format off
template <typename T, typename U>
struct _swap_no_throw : bool_constant<noexcept(swap(declval<T>(), declval<U>())) && noexcept(swap(declval<U>(), declval<T>()))> { }; // NOLINT

template <typename T, typename U>
struct is_nothrow_swappable_with : bool_constant<conjunction_v<is_swappable_with<T, U>, _swap_no_throw<T, U>>> {};

template <typename T, typename U>
inline constexpr bool is_nothrow_swappable_with_v = is_nothrow_swappable_with<T, U>::value;
// clang-format on

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_WITH_HPP