/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_INVOCABLE_R_HPP
#define TETL_TYPE_TRAITS_IS_INVOCABLE_R_HPP

#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_invocable.hpp"

namespace etl {

template <typename R, typename Fn, typename... ArgTypes>
struct is_invocable_r : detail::is_invocable_impl<invoke_result<Fn, ArgTypes...>, R>::type {
};

template <typename R, typename Fn, typename... ArgTypes>
inline constexpr auto is_invocable_r_v = is_invocable_r<R, Fn, ArgTypes...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_INVOCABLE_R_HPP
