// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_SCOPE_SCOPE_GUARD_HPP
#define TETL_SCOPE_SCOPE_GUARD_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl::detail {
template <typename FuncT, typename PolicyT>
struct scope_guard {
public:
    template <typename Functor>
    explicit constexpr scope_guard(Functor&& f) : _func { etl::forward<Functor>(f) }
    {
    }

    constexpr scope_guard(scope_guard&& rhs) noexcept
        : _func { etl::move(rhs._func) }, _policy { etl::move(rhs._policy) }
    {
    }

    ~scope_guard()
    {
        if (_policy) { _func(); }
    }

    constexpr auto release() noexcept -> void { _policy.release(); }

    scope_guard(scope_guard const&)                    = delete;
    auto operator=(scope_guard const&) -> scope_guard& = delete;
    auto operator=(scope_guard&&) -> scope_guard&      = delete;

private:
    FuncT _func;
    PolicyT _policy {};
};

struct scope_exit_impl {
    constexpr scope_exit_impl() = default;
    constexpr scope_exit_impl(scope_exit_impl&& rhs) noexcept : should_execute { rhs.should_execute } { rhs.release(); }
    constexpr auto release() noexcept -> void { should_execute = false; }
    explicit constexpr operator bool() const noexcept { return should_execute; }
    bool should_execute = true;
};
} // namespace etl::detail

#endif // TETL_SCOPE_SCOPE_GUARD_HPP
