

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

#ifndef TETL_FUNCTIONAL_FUNCTION_REF_HPP
#define TETL_FUNCTIONAL_FUNCTION_REF_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_invocable_r.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/swap.hpp"

namespace etl {

template <typename Signature>
struct function_ref;

template <typename R, typename... Args>
struct function_ref<R(Args...)> {
private:
    using function_ptr_t = R (*)(Args...);

    void* obj_ { nullptr };
    R (*callable_)(void*, Args...);

    template <typename F>
    inline static constexpr bool invocable_ = is_invocable_r_v<R, F&&, Args...>;

    template <typename F>
    using invocable_and_not_function_ref
        = enable_if_t<!is_same_v<decay_t<F>, function_ref> && invocable_<F>,
            int>;

public:
    function_ref() noexcept = delete;

    template <typename F, invocable_and_not_function_ref<F> = 0>
    function_ref(F&& f)
        : obj_(const_cast<void*>(reinterpret_cast<const void*>(addressof(f))))
        , callable_ { +[](void* obj, Args... args) -> R {
            return invoke(*reinterpret_cast<add_pointer_t<F>>(obj),
                forward<Args>(args)...);
        } }
    {
    }

    function_ref(function_ref const&) noexcept = default;

    template <typename F, enable_if_t<invocable_<F>, int> = 0>
    auto operator=(F&& f) noexcept -> function_ref&
    {
        obj_      = reinterpret_cast<void*>(addressof(f));
        callable_ = +[](void* obj, Args... args) {
            return invoke(*reinterpret_cast<add_pointer_t<F>>(obj),
                forward<Args>(args)...);
        };

        return *this;
    }

    function_ref& operator=(function_ref const&) noexcept = default;

    auto swap(function_ref& other) noexcept -> void
    {
        using etl::swap;
        swap(obj_, other.obj_);
        swap(callable_, other.callable_);
    }

    auto operator()(Args... args) const noexcept -> R
    {
        return callable_(obj_, forward<Args>(args)...);
    }
};

template <typename R, typename... Args>
function_ref(R (*)(Args...)) -> function_ref<R(Args...)>;

template <typename R, typename... Args>
auto swap(function_ref<R(Args...)>& lhs, function_ref<R(Args...)>& rhs) noexcept
    -> void
{
    lhs.swap(rhs);
}
} // namespace etl

#endif // TETL_FUNCTIONAL_FUNCTION_REF_HPP