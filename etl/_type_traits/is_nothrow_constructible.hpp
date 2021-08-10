// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

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
    = nothrow_constructible_impl<TETL_IS_CONSTRUCTIBLE(T, Args...), T, Args...>;
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