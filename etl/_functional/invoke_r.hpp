/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_INVOKE_R_HPP
#define TETL_FUNCTIONAL_INVOKE_R_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_invocable_r.hpp"
#include "etl/_type_traits/is_void.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

/// \todo Add noexcept(is_nothrow_invocable_r_v<R, F, Args...>)
template <typename R, typename F, typename... Args, enable_if_t<is_invocable_r_v<R, F, Args...>, int> = 0>
constexpr auto invoke_r(F&& f, Args&&... args) -> R
{
    if constexpr (is_void_v<R>) {
        invoke(forward<F>(f), forward<Args>(args)...);
    } else {
        return invoke(forward<F>(f), forward<Args>(args)...);
    }
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INVOKE_R_HPP
