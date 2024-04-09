// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/void_t.hpp>

namespace etl {

namespace detail {
template <typename, typename T, typename... Args>
struct is_constructible_helper : false_type { };

template <typename T, typename... Args>
struct is_constructible_helper<void_t<decltype(T(declval<Args>()...))>, T, Args...> : true_type { };
} // namespace detail

template <typename T, typename... Args>
using is_constructible = detail::is_constructible_helper<void_t<>, T, Args...>;

template <typename T, typename... Args>
inline constexpr bool is_constructible_v = is_constructible<T, Args...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP
