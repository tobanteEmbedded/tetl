// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_INVOKE_HPP
#define TETL_FUNCTIONAL_INVOKE_HPP

#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/invoke_result.hpp>
#include <etl/_type_traits/is_base_of.hpp>
#include <etl/_type_traits/is_function.hpp>
#include <etl/_type_traits/is_member_pointer.hpp>
#include <etl/_type_traits/is_object.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

namespace detail {

template <typename C, typename Pointed, typename T1, typename... Args>
constexpr auto invoke_memptr(Pointed C::*f, T1&& t1, Args&&... args) -> decltype(auto)
{
    if constexpr (is_function_v<Pointed>) {
        if constexpr (is_base_of_v<C, decay_t<T1>>) {
            return (TETL_FORWARD(t1).*f)(TETL_FORWARD(args)...);
        } else if constexpr (is_reference_wrapper_v<decay_t<T1>>) {
            return (t1.get().*f)(TETL_FORWARD(args)...);
        } else {
            return ((*TETL_FORWARD(t1)).*f)(TETL_FORWARD(args)...);
        }
    } else {
        static_assert(is_object_v<Pointed> && sizeof...(args) == 0);
        if constexpr (is_base_of_v<C, decay_t<T1>>) {
            return TETL_FORWARD(t1).*f;
        } else if constexpr (is_reference_wrapper_v<decay_t<T1>>) {
            return t1.get().*f;
        } else {
            return (*TETL_FORWARD(t1)).*f;
        }
    }
}
} // namespace detail

/// \todo Add noexcept(is_nothrow_invocable_v<F, Args...>)
template <typename F, typename... Args>
constexpr auto invoke(F&& f, Args&&... args) -> invoke_result_t<F, Args...>
{
    if constexpr (is_member_pointer_v<decay_t<F>>) {
        return detail::invoke_memptr(f, TETL_FORWARD(args)...);
    } else {
        return TETL_FORWARD(f)(TETL_FORWARD(args)...);
    }
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INVOKE_HPP
