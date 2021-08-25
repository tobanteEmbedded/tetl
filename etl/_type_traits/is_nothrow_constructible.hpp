/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_CONSTRUCTIBLE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/meta.hpp"
#include "etl/_type_traits/remove_all_extents.hpp"

namespace etl {

namespace detail {
template <bool, typename T, typename... Args>
struct nothrow_constructible_impl : false_type {
};

template <typename T, typename... Args>
struct nothrow_constructible_impl<true, T, Args...>
    : bool_constant<noexcept(T(declval<Args>()...))> {
};

template <typename T, typename Arg>
struct nothrow_constructible_impl<true, T, Arg>
    : bool_constant<noexcept(static_cast<T>(declval<Arg>()))> {
};

template <typename T>
struct nothrow_constructible_impl<true, T> : bool_constant<noexcept(T())> {
};

template <typename T, size_t Size>
struct nothrow_constructible_impl<true, T[Size]>
    : bool_constant<noexcept(remove_all_extents_t<T>())> {
};

#if defined(__cpp_aggregate_paren_init)
template <typename T, size_t Size, typename Arg>
struct nothrow_constructible_impl<true, T[Size], Arg>
    : nothrow_constructible_impl<true, T, Arg> {
};

template <typename T, size_t Size, typename... Args>
struct nothrow_constructible_impl<true, T[Size], Args...>
    : meta_and<nothrow_constructible_impl<true, T, Args>...> {
};
#endif

template <typename T, typename... Args>
using is_nothrow_constructible_helper
    = nothrow_constructible_impl<TETL_BUILTIN_IS_CONSTRUCTIBLE(T, Args...), T,
        Args...>;
} // namespace detail

/// \brief The variable definition does not call any operation that is not
/// trivial. For the purposes of this check, the call to etl::declval is
/// considered trivial.
template <typename T, typename... Args>
struct is_nothrow_constructible
    : detail::is_nothrow_constructible_helper<T, Args...>::type {
};

template <typename T, typename... Args>
inline constexpr bool is_nothrow_constructible_v
    = is_nothrow_constructible<T, Args...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_CONSTRUCTIBLE_HPP