// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP
#define TETL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

template <typename T>
struct is_swappable;

template <typename T>
struct is_nothrow_swappable;

// clang-format off
template <typename T>
requires(is_move_constructible_v<T> && is_move_assignable_v<T>)
constexpr auto swap(T& a, T& b) noexcept(is_nothrow_move_constructible_v<T> && is_nothrow_move_assignable_v<T>) -> void;

template<typename T, size_t N>
requires(is_swappable<T>::value)
constexpr auto swap(T (&a)[N], T (&b)[N]) noexcept(is_nothrow_swappable<T>::value) -> void;

// swap(declval<T>(), declval<U>()) is not valid
template <typename T, typename U, typename = void>
struct _swappable_with_helper : false_type { }; // NOLINT

// swap(declval<T>(), declval<U>()) is valid
template <typename T, typename U>
struct _swappable_with_helper<T, U, void_t<decltype(swap(declval<T>(), declval<U>()))>> : true_type { }; // NOLINT

// Determine if expressions with type and value category T and U can be
// swapped (and vice versa)
template <typename T, typename U>
struct is_swappable_with : bool_constant<conjunction_v<_swappable_with_helper<T, U>, _swappable_with_helper<U, T>>> {};

template <typename T, typename U>
inline constexpr bool is_swappable_with_v = is_swappable_with<T, U>::value;

// clang-format on

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP
