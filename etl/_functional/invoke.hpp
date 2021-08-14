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
constexpr auto invoke_memptr(Pointed C::*f, T1&& t1, Args&&... args)
    -> decltype(auto)
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
    if constexpr (is_member_pointer_v<decay_t<F>>)
        return detail::invoke_memptr(f, forward<Args>(args)...);
    else
        return forward<F>(f)(forward<Args>(args)...);
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INVOKE_HPP