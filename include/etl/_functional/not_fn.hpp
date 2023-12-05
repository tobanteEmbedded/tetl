// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_NOT_FN_HPP
#define TETL_FUNCTIONAL_NOT_FN_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_type_traits/is_member_pointer.hpp"
#include "etl/_type_traits/is_pointer.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {

// clang-format off
template <typename F, typename... Args>
concept negate_invocable = requires(F&& f, Args&&... args) {
    not etl::invoke(etl::forward<F>(f), etl::forward<Args>(args)...);
};
// clang-format on

template <typename F>
struct not_fn_t {
    F f;

    template <typename... Args>
        requires(negate_invocable<F&, Args...>)
    constexpr auto operator()(Args&&... args) & noexcept(noexcept(not etl::invoke(f, etl::forward<Args>(args)...)))
        -> decltype(auto)
    {
        return not etl::invoke(f, etl::forward<Args>(args)...);
    }

    template <typename... Args>
        requires(negate_invocable<F const&, Args...>)
    constexpr auto operator()(Args&&... args) const& noexcept(noexcept(not etl::invoke(f, etl::forward<Args>(args)...)))
        -> decltype(auto)
    {
        return not etl::invoke(f, etl::forward<Args>(args)...);
    }

    template <typename... Args>
        requires(negate_invocable<F, Args...>)
    constexpr auto operator()(Args&&... args) && noexcept(
        noexcept(not etl::invoke(etl::move(f), etl::forward<Args>(args)...))) -> decltype(auto)
    {
        return not etl::invoke(etl::move(f), etl::forward<Args>(args)...);
    }

    template <typename... Args>
        requires(negate_invocable<F const, Args...>)
    constexpr auto operator()(Args&&... args) const&& noexcept(
        noexcept(not etl::invoke(etl::move(f), etl::forward<Args>(args)...))) -> decltype(auto)
    {
        return not etl::invoke(etl::move(f), etl::forward<Args>(args)...);
    }

    template <typename... Args>
        requires(not negate_invocable<F&, Args...>)
    auto operator()(Args&&...) & -> void = delete;

    template <typename... Args>
        requires(not negate_invocable<F const&, Args...>)
    auto operator()(Args&&...) const& -> void = delete;

    template <typename... Args>
        requires(not negate_invocable<F, Args...>)
    auto operator()(Args&&...) && -> void = delete;

    template <typename... Args>
        requires(not negate_invocable<F const, Args...>)
    auto operator()(Args&&...) const&& -> void = delete;
};

template <auto ConstFn>
struct stateless_not_fn {
    template <typename... Args>
    constexpr auto operator()(Args&&... args) const
        noexcept(noexcept(!etl::invoke(ConstFn, etl::forward<Args>(args)...)))
            -> decltype(!etl::invoke(ConstFn, etl::forward<Args>(args)...))
    {
        return !etl::invoke(ConstFn, etl::forward<Args>(args)...);
    }
};

} // namespace detail

template <typename F>
[[nodiscard]] constexpr auto not_fn(F&& f) -> detail::not_fn_t<etl::decay_t<F>>
{
    return {etl::forward<F>(f)};
}

template <auto ConstFn>
[[nodiscard]] constexpr auto not_fn() noexcept -> detail::stateless_not_fn<ConstFn>
{
    if constexpr (etl::is_pointer_v<decltype(ConstFn)> or etl::is_member_pointer_v<decltype(ConstFn)>) {
        static_assert(ConstFn != nullptr);
    }
    return {};
}

} // namespace etl

#endif // TETL_FUNCTIONAL_NOT_FN_HPP
