

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

/// Non-owning view of a callable.
///
/// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p0792r4.html
/// https://github.com/TartanLlama/function_ref
template <typename R, typename... Args>
struct function_ref<R(Args...)> {
private:
    using internal_signature_t = R (*)(void*, Args...);

    void* obj_ { nullptr };
    internal_signature_t callable_ { nullptr };

    template <typename F>
    inline static constexpr bool invocable_ = is_invocable_r_v<R, F&&, Args...>;

    template <typename F>
    using enable_if_invocable = enable_if_t<invocable_<F>, int>;

    template <typename F>
    using enable_if_invocable_and_not_function_ref
        = enable_if_t<!is_same_v<decay_t<F>, function_ref> && invocable_<F>,
            int>;

public:
    /// \brief Constructs a function_ref referring to f.
    template <typename F, enable_if_invocable_and_not_function_ref<F> = 0>
    function_ref(F&& f) noexcept
        : obj_(const_cast<void*>(reinterpret_cast<const void*>(addressof(f))))
        , callable_ {
            +[](void* obj, Args... args) -> R {
                auto* func = reinterpret_cast<add_pointer_t<F>>(obj);
                return invoke(*func, forward<Args>(args)...);
            },
        }
    {
    }

    /// \brief Reassigns this function_ref to refer to f.
    template <typename F, enable_if_invocable<F> = 0>
    auto operator=(F&& f) noexcept -> function_ref&
    {
        obj_      = reinterpret_cast<void*>(addressof(f));
        callable_ = +[](void* obj, Args... args) {
            auto* func = reinterpret_cast<add_pointer_t<F>>(obj);
            return invoke(*func, forward<Args>(args)...);
        };

        return *this;
    }

    function_ref(function_ref const& /*other*/) = default;

    auto operator=(function_ref const& /*other*/) -> function_ref& = default;

    /// Exchanges the values of *this and rhs.
    auto swap(function_ref& other) noexcept -> void
    {
        using etl::swap;
        swap(obj_, other.obj_);
        swap(callable_, other.callable_);
    }

    ///  Equivalent to return invoke(f, forward<Args>(args)...);, where f is the
    ///  callable object referred to by *this, qualified with the same
    ///  cv-qualifiers as the function type Signature.
    auto operator()(Args... args) const -> R
    {
        return callable_(obj_, forward<Args>(args)...);
    }
};

template <typename R, typename... Args>
function_ref(R (*)(Args...)) -> function_ref<R(Args...)>;

/// Exchanges the values of lhs and rhs. Equivalent to lhs.swap(rhs).
template <typename R, typename... Args>
auto swap(function_ref<R(Args...)>& lhs, function_ref<R(Args...)>& rhs) noexcept
    -> void
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_FUNCTIONAL_FUNCTION_REF_HPP