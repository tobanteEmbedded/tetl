// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COROUTINE_COROUTINE_TRAITS_HPP
#define TETL_COROUTINE_COROUTINE_TRAITS_HPP

#include <etl/_type_traits/void_t.hpp>

#if defined(__cpp_coroutines)

namespace etl {

namespace detail {
template <typename R, typename = void>
struct coro_traits { };

template <typename R>
struct coro_traits<R, void_t<typename R::promise_type>> {
    using promise_type = typename R::promise_type;
};
} // namespace detail

template <typename R, typename... Args>
struct coroutine_traits : detail::coro_traits<R> { };

} // namespace etl

#endif // defined(__cpp_coroutines)

#endif // TETL_COROUTINE_COROUTINE_TRAITS_HPP
