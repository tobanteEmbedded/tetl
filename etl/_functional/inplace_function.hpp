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

#ifndef TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP
#define TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP

#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_invocable_r.hpp"
#include "etl/_utility/exchange.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/swap.hpp"

#ifndef TETL_THROW
// #define TETL_THROW(x) throw(x)
#define TETL_THROW(x)
#endif

namespace etl {

struct bad_function_call {
};

namespace detail {

template <typename T>
struct wrapper {
    using type = T;
};

template <typename R, typename... Args>
struct inplace_function_vtable {
    using storage_ptr_t = void*;

    using invoke_ptr_t     = R (*)(storage_ptr_t, Args&&...);
    using process_ptr_t    = void (*)(storage_ptr_t, storage_ptr_t);
    using destructor_ptr_t = void (*)(storage_ptr_t);

    const invoke_ptr_t invoke_ptr;
    const process_ptr_t copy_ptr;
    const process_ptr_t relocate_ptr;
    const destructor_ptr_t destructor_ptr;

    explicit constexpr inplace_function_vtable() noexcept
        : invoke_ptr { [](storage_ptr_t, Args&&...) -> R {
            TETL_THROW(bad_function_call {});
        } }
        , copy_ptr { [](storage_ptr_t, storage_ptr_t) -> void {} }
        , relocate_ptr { [](storage_ptr_t, storage_ptr_t) -> void {} }
        , destructor_ptr { [](storage_ptr_t) -> void {} }
    {
    }

    template <typename C>
    explicit constexpr inplace_function_vtable(wrapper<C> /*ignore*/) noexcept
        : invoke_ptr { [](storage_ptr_t storage_ptr, Args&&... args) -> R {
            return (*static_cast<C*>(storage_ptr))(
                static_cast<Args&&>(args)...);
        } }
        , copy_ptr { [](storage_ptr_t dst_ptr, storage_ptr_t src_ptr) -> void {
            ::new (dst_ptr) C { (*static_cast<C*>(src_ptr)) };
        } }
        , relocate_ptr { [](storage_ptr_t dst_ptr,
                             storage_ptr_t src_ptr) -> void {
            ::new (dst_ptr) C { etl::move(*static_cast<C*>(src_ptr)) };
            static_cast<C*>(src_ptr)->~C();
        } }
        , destructor_ptr { [](storage_ptr_t src_ptr) -> void {
            static_cast<C*>(src_ptr)->~C();
        } }
    {
    }

    inplace_function_vtable(inplace_function_vtable const&) = delete;
    inplace_function_vtable(inplace_function_vtable&&)      = delete;

    inplace_function_vtable& operator=(inplace_function_vtable const&) = delete;
    inplace_function_vtable& operator=(inplace_function_vtable&&) = delete;

    ~inplace_function_vtable() = default;
};

template <typename R, typename... Args>
inline constexpr inplace_function_vtable<R, Args...> empty_vtable {};

template <size_t DstCap, size_t DstAlign, size_t SrcCap, size_t SrcAlign>
struct is_valid_inplace_destination : etl::true_type {
    static_assert(DstCap >= SrcCap);
    static_assert(DstAlign % SrcAlign == 0);
};

} // namespace detail

template <typename Signature, size_t Capacity = sizeof(void*),
    size_t Alignment = alignof(aligned_storage_t<Capacity>)>
struct inplace_function;

namespace detail {
template <typename>
struct is_inplace_function : false_type {
};
template <typename Sig, size_t Cap, size_t Align>
struct is_inplace_function<inplace_function<Sig, Cap, Align>> : etl::true_type {
};
} // namespace detail

template <typename R, typename... Args, size_t Capacity, size_t Alignment>
struct inplace_function<R(Args...), Capacity, Alignment> {
private:
    using storage_t    = aligned_storage_t<Capacity, Alignment>;
    using vtable_t     = detail::inplace_function_vtable<R, Args...>;
    using vtable_ptr_t = vtable_t const*;

    template <typename, size_t, size_t>
    friend struct inplace_function;

public:
    using capacity  = integral_constant<size_t, Capacity>;
    using alignment = integral_constant<size_t, Alignment>;

    inplace_function() noexcept
        : vtable_ { addressof(detail::empty_vtable<R, Args...>) }
    {
    }

    // clang-format off
    template <typename T, typename C = decay_t<T>, typename = enable_if_t<!detail::is_inplace_function<C>::value && is_invocable_r_v<R, C&, Args...>>>
    inplace_function(T&& closure)
    {
        static_assert(is_copy_constructible_v<C>, "inplace_function cannot be constructed from non-copyable type");
        static_assert(sizeof(C) <= Capacity, "inplace_function cannot be constructed from object with this (large) size");
        static_assert(Alignment % alignof(C) == 0, "inplace_function cannot be constructed from object with this (large) alignment");
        // clang-format on

        static vtable_t const vt { detail::wrapper<C> {} };
        vtable_ = addressof(vt);

        ::new (addressof(storage_)) C { forward<T>(closure) };
    }

    template <size_t Cap, size_t Align>
    inplace_function(inplace_function<R(Args...), Cap, Align> const& other)
        : inplace_function {
            other.vtable_,
            other.vtable_->copy_ptr,
            addressof(other.storage_),
        }
    {
        static_assert(detail::is_valid_inplace_destination<Capacity, Alignment,
                          Cap, Align>::value,
            "conversion not allowed");
    }

    template <size_t Cap, size_t Align>
    inplace_function(inplace_function<R(Args...), Cap, Align>&& other) noexcept
        : inplace_function {
            other.vtable_,
            other.vtable_->relocate_ptr,
            addressof(other.storage_),
        }
    {
        static_assert(detail::is_valid_inplace_destination<Capacity, Alignment,
                          Cap, Align>::value,
            "conversion not allowed");

        other.vtable_ = addressof(detail::empty_vtable<R, Args...>);
    }

    inplace_function(nullptr_t) noexcept
        : vtable_ { addressof(detail::empty_vtable<R, Args...>) }
    {
    }

    inplace_function(inplace_function const& other) : vtable_ { other.vtable_ }
    {
        vtable_->copy_ptr(addressof(storage_), addressof(other.storage_));
    }

    inplace_function(inplace_function&& other) noexcept
        : vtable_ { exchange(
            other.vtable_, addressof(detail::empty_vtable<R, Args...>)) }
    {
        vtable_->relocate_ptr(addressof(storage_), addressof(other.storage_));
    }

    auto operator=(nullptr_t) noexcept -> inplace_function&
    {
        vtable_->destructor_ptr(addressof(storage_));
        vtable_ = addressof(detail::empty_vtable<R, Args...>);
        return *this;
    }

    auto operator=(inplace_function other) noexcept -> inplace_function&
    {
        vtable_->destructor_ptr(addressof(storage_));

        vtable_ = exchange(
            other.vtable_, addressof(detail::empty_vtable<R, Args...>));
        vtable_->relocate_ptr(addressof(storage_), addressof(other.storage_));
        return *this;
    }

    ~inplace_function() { vtable_->destructor_ptr(addressof(storage_)); }

    auto operator()(Args... args) const -> R
    {
        return vtable_->invoke_ptr(addressof(storage_), forward<Args>(args)...);
    }

    [[nodiscard]] constexpr auto operator==(nullptr_t) const noexcept -> bool
    {
        return !operator bool();
    }

    [[nodiscard]] constexpr auto operator!=(nullptr_t) const noexcept -> bool
    {
        return operator bool();
    }

    [[nodiscard]] explicit constexpr operator bool() const noexcept
    {
        return vtable_ != addressof(detail::empty_vtable<R, Args...>);
    }

    auto swap(inplace_function& other) noexcept -> void
    {
        if (this == addressof(other)) { return; }

        auto tmp = storage_t {};
        vtable_->relocate_ptr(addressof(tmp), addressof(storage_));

        other.vtable_->relocate_ptr(
            addressof(storage_), addressof(other.storage_));

        vtable_->relocate_ptr(addressof(other.storage_), addressof(tmp));

        swap(vtable_, other.vtable_);
    }

private:
    vtable_ptr_t vtable_;
    storage_t mutable storage_;

    inplace_function(vtable_ptr_t vtable_ptr,
        typename vtable_t::process_ptr_t process_ptr,
        typename vtable_t::storage_ptr_t storage_ptr)
        : vtable_ { vtable_ptr }
    {
        process_ptr(addressof(storage_), storage_ptr);
    }
};

template <typename R, typename... Args, size_t Capacity, size_t Alignment>
auto swap(inplace_function<R(Args...), Capacity, Alignment>& lhs,
    inplace_function<R(Args...), Capacity, Alignment>& rhs) noexcept -> void
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP