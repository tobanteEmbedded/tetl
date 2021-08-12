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

#ifndef TETL_TYPE_TRAITS_INVOKE_RESULT_HPP
#define TETL_TYPE_TRAITS_INVOKE_RESULT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/is_function.hpp"

namespace etl {

template <class T>
struct reference_wrapper;

namespace detail {
template <typename T>
constexpr auto xforward(remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <typename T>
struct is_reference_wrapper : ::etl::false_type {
};

// TODO: Enable once reference_wrapper is implemented.
template <typename U>
struct is_reference_wrapper<::etl::reference_wrapper<U>> : ::etl::true_type {
};

template <typename T>
struct invoke_impl {
    template <typename F, typename... Args>
    static auto call(F&& f, Args&&... args)
        -> decltype(xforward<F>(f)(xforward<Args>(args)...));
};

template <typename B, typename MT>
struct invoke_impl<MT B::*> {
    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<::etl::is_base_of_v<B, Td>>>
    static auto get(T&& t) -> T&&;

    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<is_reference_wrapper<Td>::value>>
    static auto get(T&& t) -> decltype(t.get());

    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<!::etl::is_base_of_v<B, Td>>,
        typename = ::etl::enable_if_t<!is_reference_wrapper<Td>::value>>
    static auto get(T&& t) -> decltype(*xforward<T>(t));

    template <typename T, typename... Args, typename MT1,
        typename = ::etl::enable_if_t<::etl::is_function_v<MT1>>>
    static auto call(MT1 B::*pmf, T&& t, Args&&... args) -> decltype((
        invoke_impl::get(xforward<T>(t)).*pmf)(xforward<Args>(args)...));

    template <typename T>
    static auto call(MT B::*pmd, T&& t)
        -> decltype(invoke_impl::get(xforward<T>(t)).*pmd);
};

template <typename F, typename... Args, typename Fd = ::etl::decay_t<F>>
auto INVOKE(F&& f, Args&&... args)
    -> decltype(invoke_impl<Fd>::call(xforward<F>(f), xforward<Args>(args)...));

template <typename AlwaysVoid, typename, typename...>
struct invoke_result {
};
template <typename F, typename... Args>
struct invoke_result<decltype(void(detail::INVOKE(
                         ::etl::declval<F>(), ::etl::declval<Args>()...))),
    F, Args...> {
    using type = decltype(detail::INVOKE(
        ::etl::declval<F>(), ::etl::declval<Args>()...));
};
} // namespace detail

/// \brief Deduces the return type of an INVOKE expression at compile time.
/// F and all types in ArgTypes can be any complete type, array of unknown
/// bound, or (possibly cv-qualified) void. The behavior of a program that adds
/// specializations for any of the templates described on this page is
/// undefined. This implementation is copied from **cppreference.com**.
///
/// \notes
/// [cppreference.com/w/cpp/types/result_of](https://en.cppreference.com/w/cpp/types/result_of)
/// \group invoke_result
template <typename F, typename... ArgTypes>
struct invoke_result : detail::invoke_result<void, F, ArgTypes...> {
};

/// \group invoke_result
template <typename F, typename... ArgTypes>
using invoke_result_t = typename invoke_result<F, ArgTypes...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_INVOKE_RESULT_HPP