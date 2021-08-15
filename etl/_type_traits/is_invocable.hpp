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

#ifndef TETL_TYPE_TRAITS_IS_INVOCABLE_HPP
#define TETL_TYPE_TRAITS_IS_INVOCABLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_void.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

// clang-format off
namespace detail {
    
template <typename Result, typename Ret, bool = etl::is_void_v<Ret>, typename = void>
struct is_invocable_impl : etl::false_type { };

template <typename Result, typename Ret>
struct is_invocable_impl<Result, Ret, true, etl::void_t<typename Result::type>> : etl::true_type { };

// Check if the return type can be converted to T
template <typename Result, typename Ret>
struct is_invocable_impl<Result, Ret, false, etl::void_t<typename Result::type>> {
    static auto _get() -> typename Result::type;
    template <typename T> static auto _use(T) -> void;
    template <typename T, typename = decltype(_use<T>(_get()))> static auto _check(int) -> etl::true_type;
    template <typename T> static auto _check(...) -> etl::false_type;
    using type = decltype(_check<Ret>(1));
};

} // namespace detail
// clang-format on

template <typename Fn, typename... ArgTypes>
struct is_invocable
    : detail::is_invocable_impl<invoke_result<Fn, ArgTypes...>, void>::type {
};

template <typename Fn, typename... ArgTypes>
inline constexpr auto is_invocable_v = is_invocable<Fn, ArgTypes...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_INVOCABLE_HPP