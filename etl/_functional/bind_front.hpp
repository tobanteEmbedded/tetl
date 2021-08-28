/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_BIND_FRONT_HPP
#define TETL_FUNCTIONAL_BIND_FRONT_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_tuple/apply.hpp"
#include "etl/_tuple/tuple.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/unwrap_reference.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {

template <typename Func, typename BoundArgsTuple, typename... CallArgs>
constexpr auto bind_front_caller(Func&& func, BoundArgsTuple&& boundArgsTuple,
    CallArgs&&... callArgs) -> decltype(auto)
{
    return etl::apply(
        [&func, &callArgs...](auto&&... boundArgs) -> decltype(auto) {
            return etl::invoke(etl::forward<Func>(func),
                etl::forward<decltype(boundArgs)>(boundArgs)...,
                etl::forward<CallArgs>(callArgs)...);
        },
        etl::forward<BoundArgsTuple>(boundArgsTuple));
}

template <typename Func, typename... BoundArgs>
class bind_front_t {
public:
    template <typename F, typename... BA,
        etl::enable_if_t<
            !(sizeof...(BA) == 0
                && etl::is_base_of_v<bind_front_t, etl::decay_t<F>>),
            bool> = true>
    explicit bind_front_t(F&& f, BA&&... ba)
        : func_(etl::forward<F>(f)), boundArgs_(etl::forward<BA>(ba)...)
    {
    }

    // TODO: Add noexcept(etl::is_nothrow_invocable_v<Func&, BoundArgs&...,
    // CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) & -> etl::invoke_result_t<Func&,
        BoundArgs&..., CallArgs...>
    {
        return bind_front_caller(
            func_, boundArgs_, etl::forward<CallArgs>(callArgs)...);
    }

    // TODO: Add noexcept(etl::is_nothrow_invocable_v<Func const&, BoundArgs
    // const&...,CallArgs...>)
    template <typename... CallArgs>
    auto operator()(
        CallArgs&&... callArgs) const& -> etl::invoke_result_t<Func const&,
        BoundArgs const&..., CallArgs...>
    {
        return bind_front_caller(
            func_, boundArgs_, etl::forward<CallArgs>(callArgs)...);
    }

    // TODO: Add  noexcept(etl::is_nothrow_invocable_v<Func, BoundArgs...,
    // CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) && -> etl::invoke_result_t<Func,
        BoundArgs..., CallArgs...>
    {
        return bind_front_caller(etl::move(func_), etl::move(boundArgs_),
            etl::forward<CallArgs>(callArgs)...);
    }

    // TODO: noexcept(etl::is_nothrow_invocable_v<Func const, BoundArgs
    // const...,CallArgs...>)
    template <typename... CallArgs>
    auto operator()(
        CallArgs&&... callArgs) const&& -> etl::invoke_result_t<Func const,
        BoundArgs const..., CallArgs...>
    {
        return bind_front_caller(etl::move(func_), etl::move(boundArgs_),
            etl::forward<CallArgs>(callArgs)...);
    }

private:
    Func func_;
    etl::tuple<BoundArgs...> boundArgs_;
};

} // namespace detail

/// \brief The function template bind_front generates a forwarding call wrapper
/// for f. Calling this wrapper is equivalent to invoking f with its first
/// sizeof...(Args) parameters bound to args. In other words, etl::bind_front(f,
/// bound_args...)(call_args...) is equivalent to etl::invoke(f, bound_args...,
/// call_args....).
///
/// \details Copied implementation from paper:
/// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0356r5.html
template <typename Func, typename... BoundArgs>
constexpr auto bind_front(Func&& func, BoundArgs&&... boundArgs)
{
    return detail::bind_front_t<etl::decay_t<Func>,
        etl::unwrap_ref_decay_t<BoundArgs>...> { etl::forward<Func>(func),
        etl::forward<BoundArgs>(boundArgs)... };
}

} // namespace etl

#endif // TETL_FUNCTIONAL_BIND_FRONT_HPP