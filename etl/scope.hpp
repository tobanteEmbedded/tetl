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

#ifndef TETL_SCOPE_HPP
#define TETL_SCOPE_HPP

#include "etl/version.hpp"

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

/// \brief The class template `scope_exit` is a general-purpose scope guard
/// intended to call its exit function when a scope is exited. \details A
/// `scope_exit` may be either active, i.e. calls its exit function on
/// destruction, or inactive, i.e. does nothing on destruction. A `scope_exit`
/// is active after constructed from an exit function. A `scope_exit` can become
/// inactive by calling `release()` on it either manually or automatically (by
/// the move constructor). An inactive `scope_exit` may also be obtained by
/// initializing with another inactive `scope_exit`. Once a `scope_exit` is
/// inactive, it cannot become active again.
template <typename FuncT>
struct scope_exit : detail::scope_guard<FuncT, detail::scope_exit_impl> {
    /// Creates a scope_exit from a function, a function object or another
    /// scope_exit.
    using detail::scope_guard<FuncT, detail::scope_exit_impl>::scope_guard;
};

// Deduction guide
template <typename FuncT>
scope_exit(FuncT) -> scope_exit<decay_t<FuncT>>;
} // namespace etl

#endif // TETL_SCOPE_HPP