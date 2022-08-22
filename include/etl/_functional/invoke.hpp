/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_INVOKE_HPP
#define TETL_FUNCTIONAL_INVOKE_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/is_member_pointer.hpp"
#include "etl/_type_traits/is_object.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

namespace detail {

template <typename C, typename Pointed, typename T1, typename... Args>
constexpr auto invoke_memptr(Pointed C::*f, T1&& t1, Args&&... args) -> decltype(auto)
{
    if constexpr (etl::is_function_v<Pointed>) {
        if constexpr (etl::is_base_of_v<C, etl::decay_t<T1>>) {
            return (etl::forward<T1>(t1).*f)(etl::forward<Args>(args)...);
        } else if constexpr (is_reference_wrapper_v<etl::decay_t<T1>>) {
            return (t1.get().*f)(etl::forward<Args>(args)...);
        } else {
            return ((*etl::forward<T1>(t1)).*f)(etl::forward<Args>(args)...);
        }
    } else {
        static_assert(etl::is_object_v<Pointed> && sizeof...(args) == 0);
        if constexpr (etl::is_base_of_v<C, etl::decay_t<T1>>) {
            return etl::forward<T1>(t1).*f;
        } else if constexpr (is_reference_wrapper_v<etl::decay_t<T1>>) {
            return t1.get().*f;
        } else {
            return (*etl::forward<T1>(t1)).*f;
        }
    }
}
} // namespace detail

// todo Add noexcept(is_nothrow_invocable_v<F, Args...>)
template <typename F, typename... Args>
constexpr auto invoke(F&& f, Args&&... args) -> invoke_result_t<F, Args...>
{
    if constexpr (is_member_pointer_v<decay_t<F>>) {
        return detail::invoke_memptr(f, forward<Args>(args)...);
    } else {
        return forward<F>(f)(forward<Args>(args)...);
    }
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INVOKE_HPP
