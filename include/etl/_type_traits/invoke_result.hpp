// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_INVOKE_RESULT_HPP
#define TETL_TYPE_TRAITS_INVOKE_RESULT_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_base_of.hpp>
#include <etl/_type_traits/is_function.hpp>
#include <etl/_type_traits/is_reference_wrapper.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

namespace detail {

template <typename T>
struct invoke_impl {
    template <typename F, typename... Args>
    static auto call(F&& f, Args&&... args) -> decltype(etl::forward<F>(f)(etl::forward<Args>(args)...));
};

template <typename B, typename MT>
struct invoke_impl<MT B::*> {
    template <typename T, typename Td = decay_t<T>>
        requires is_base_of_v<B, Td>
    static auto get(T&& t) -> T&&;

    template <typename T, typename Td = decay_t<T>>
        requires is_reference_wrapper<Td>::value
    static auto get(T&& t) -> decltype(t.get());

    template <typename T, typename Td = decay_t<T>>
        requires(!is_base_of_v<B, Td> and !is_reference_wrapper<Td>::value)
    static auto get(T&& t) -> decltype(*etl::forward<T>(t));

    template <typename T, typename... Args, typename MT1>
        requires is_function_v<MT1>
    static auto call(MT1 B::* pmf, T&& t, Args&&... args)
        -> decltype((invoke_impl::get(etl::forward<T>(t)).*pmf)(etl::forward<Args>(args)...));

    template <typename T>
    static auto call(MT B::* pmd, T&& t) -> decltype(invoke_impl::get(etl::forward<T>(t)).*pmd);
};

template <typename F, typename... Args, typename Fd = decay_t<F>>
auto INVOKE(F&& f, Args&&... args) -> decltype(invoke_impl<Fd>::call(etl::forward<F>(f), etl::forward<Args>(args)...));

template <typename AlwaysVoid, typename, typename...>
struct invoke_result { };

template <typename F, typename... Args>
struct invoke_result<decltype(void(detail::INVOKE(declval<F>(), declval<Args>()...))), F, Args...> {
    using type = decltype(detail::INVOKE(declval<F>(), declval<Args>()...));
};

} // namespace detail

/// Deduces the return type of an INVOKE expression at compile time.
///
/// F and all types in ArgTypes can be any complete type, array of unknown
/// bound, or (possibly cv-qualified) void. The behavior of a program that adds
/// specializations for any of the templates described on this page is
/// undefined. This implementation is copied from **cppreference.com**.
///
/// https://en.cppreference.com/w/cpp/types/result_of
///
/// \ingroup type_traits
template <typename F, typename... ArgTypes>
struct invoke_result : detail::invoke_result<void, F, ArgTypes...> { };

/// \relates invoke_result
/// \ingroup type_traits
template <typename F, typename... ArgTypes>
using invoke_result_t = typename invoke_result<F, ArgTypes...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_INVOKE_RESULT_HPP
