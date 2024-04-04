// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_INVOKE_R_HPP
#define TETL_FUNCTIONAL_INVOKE_R_HPP

#include <etl/_functional/invoke.hpp>
#include <etl/_type_traits/is_invocable_r.hpp>
#include <etl/_type_traits/is_void.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

/// \todo Add noexcept(is_nothrow_invocable_r_v<R, F, Args...>)
template <typename R, typename F, typename... Args>
    requires(etl::is_invocable_r_v<R, F, Args...>)
constexpr auto invoke_r(F&& f, Args&&... args) -> R
{
    if constexpr (etl::is_void_v<R>) {
        etl::invoke(etl::forward<F>(f), etl::forward<Args>(args)...);
    } else {
        return etl::invoke(etl::forward<F>(f), etl::forward<Args>(args)...);
    }
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INVOKE_R_HPP
