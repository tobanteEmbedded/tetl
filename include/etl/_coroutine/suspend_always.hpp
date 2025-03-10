// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COROUTINE_SUSPEND_ALWAYS_HPP
#define TETL_COROUTINE_SUSPEND_ALWAYS_HPP

#include <etl/_coroutine/coroutine_handle.hpp>

#if defined(__cpp_coroutines)

namespace etl {

/// \ingroup coroutine
struct suspend_always {
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

#endif // TETL_COROUTINE_SUSPEND_ALWAYS_HPP
