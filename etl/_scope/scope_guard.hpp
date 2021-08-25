/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_SCOPE_SCOPE_GUARD_HPP
#define TETL_SCOPE_SCOPE_GUARD_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {
namespace detail {
template <typename FuncT, typename PolicyT>
struct scope_guard {
public:
    template <typename Functor>
    explicit scope_guard(Functor f)
        : func_ { etl::forward<Functor>(f) }, policy_ {}
    {
    }

    scope_guard(scope_guard&& rhs) noexcept
        : func_ { etl::move(rhs.func_) }, policy_ { etl::move(rhs.policy_) }
    {
    }

    ~scope_guard()
    {
        if (policy_) { func_(); }
    }

    void release() noexcept { policy_.release(); }

    scope_guard(scope_guard const&) = delete;
    auto operator=(scope_guard const&) -> scope_guard& = delete;
    auto operator=(scope_guard&&) -> scope_guard& = delete;

private:
    FuncT func_;
    PolicyT policy_;
};

struct scope_exit_impl {
    scope_exit_impl() = default;
    scope_exit_impl(scope_exit_impl&& rhs) noexcept
        : should_execute { rhs.should_execute }
    {
        rhs.release();
    }
    void release() noexcept { should_execute = false; }
    explicit operator bool() const noexcept { return should_execute; }
    bool should_execute = true;
};
} // namespace detail

} // namespace etl

#endif // TETL_SCOPE_SCOPE_GUARD_HPP