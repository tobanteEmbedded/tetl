/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COROUTINE_SUSPEND_NEVER_HPP
#define TETL_COROUTINE_SUSPEND_NEVER_HPP

#include "etl/_coroutine/coroutine_handle.hpp"

#if defined(__cpp_coroutines)

namespace etl {

struct suspend_never {
    [[nodiscard]] constexpr auto await_ready() const noexcept -> bool
    {
        (void)this;
        return false;
    }
    constexpr auto await_suspend(coroutine_handle<> /*unused*/) const noexcept -> void { (void)this; }
    constexpr auto await_resume() const noexcept -> void { (void)this; }
};

} // namespace etl

#endif // defined(__cpp_coroutines)

#endif // TETL_COROUTINE_SUSPEND_NEVER_HPP