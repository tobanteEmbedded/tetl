// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_BIND_FRONT_HPP
#define TETL_FUNCTIONAL_BIND_FRONT_HPP

#include <etl/_functional/invoke.hpp>
#include <etl/_tuple/apply.hpp>
#include <etl/_tuple/tuple.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/invoke_result.hpp>
#include <etl/_type_traits/is_base_of.hpp>
#include <etl/_type_traits/unwrap_reference.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

namespace detail {

template <typename Func, typename BoundArgsTuple, typename... CallArgs>
constexpr auto bind_front_caller(Func&& func, BoundArgsTuple&& boundArgsTuple, CallArgs&&... callArgs) -> decltype(auto)
{
    return apply([&func, &callArgs...](auto&&... boundArgs) -> decltype(auto) {
        return invoke(TETL_FORWARD(func), TETL_FORWARD(boundArgs)..., TETL_FORWARD(callArgs)...);
    }, TETL_FORWARD(boundArgsTuple));
}

template <typename Func, typename... BoundArgs>
class bind_front_t {
public:
    template <typename F, typename... BA>
        requires(!(sizeof...(BA) == 0 && is_base_of_v<bind_front_t, decay_t<F>>))
    explicit bind_front_t(F&& f, BA&&... ba) : _func(TETL_FORWARD(f))
                                             , _boundArgs(TETL_FORWARD(ba)...)
    {
    }

    // TODO: Add noexcept(is_nothrow_invocable_v<Func&, BoundArgs&...,
    // CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) & -> invoke_result_t<Func&, BoundArgs&..., CallArgs...>
    {
        return bind_front_caller(_func, _boundArgs, TETL_FORWARD(callArgs)...);
    }

    // TODO: Add noexcept(is_nothrow_invocable_v<Func const&, BoundArgs
    // const&...,CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) const& -> invoke_result_t<Func const&, BoundArgs const&..., CallArgs...>
    {
        return bind_front_caller(_func, _boundArgs, TETL_FORWARD(callArgs)...);
    }

    // TODO: Add  noexcept(is_nothrow_invocable_v<Func, BoundArgs...,
    // CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) && -> invoke_result_t<Func, BoundArgs..., CallArgs...>
    {
        return bind_front_caller(move(_func), move(_boundArgs), TETL_FORWARD(callArgs)...);
    }

    // TODO: noexcept(is_nothrow_invocable_v<Func const, BoundArgs
    // const...,CallArgs...>)
    template <typename... CallArgs>
    auto operator()(CallArgs&&... callArgs) const&& -> invoke_result_t<Func const, BoundArgs const..., CallArgs...>
    {
        return bind_front_caller(move(_func), move(_boundArgs), TETL_FORWARD(callArgs)...);
    }

private:
    Func _func;
    tuple<BoundArgs...> _boundArgs;
};

} // namespace detail

/// \brief The function template bind_front generates a forwarding call wrapper
/// for f. Calling this wrapper is equivalent to invoking f with its first
/// sizeof...(Args) parameters bound to args. In other words, bind_front(f,
/// bound_args...)(call_args...) is equivalent to invoke(f, bound_args...,
/// call_args....).
///
/// \details Copied implementation from paper:
/// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0356r5.html
template <typename Func, typename... BoundArgs>
constexpr auto bind_front(Func&& func, BoundArgs&&... boundArgs)
{
    return detail::bind_front_t<decay_t<Func>, unwrap_ref_decay_t<BoundArgs>...>{
        TETL_FORWARD(func),
        TETL_FORWARD(boundArgs)...
    };
}

} // namespace etl

#endif // TETL_FUNCTIONAL_BIND_FRONT_HPP
