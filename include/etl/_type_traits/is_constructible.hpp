/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

namespace detail {
template <typename, typename T, typename... Args>
struct is_constructible_helper : etl::false_type { };

template <typename T, typename... Args>
struct is_constructible_helper<etl::void_t<decltype(T(etl::declval<Args>()...))>, T, Args...> : etl::true_type { };
} // namespace detail

template <typename T, typename... Args>
using is_constructible = detail::is_constructible_helper<etl::void_t<>, T, Args...>;

template <typename T, typename... Args>
inline constexpr bool is_constructible_v = is_constructible<T, Args...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONSTRUCTIBLE_HPP
