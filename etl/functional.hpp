/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_FUNCTIONAL_HPP
#define TAETL_FUNCTIONAL_HPP

#include "array.hpp"
#include "byte.hpp"
#include "definitions.hpp"
#include "new.hpp"
#include "utility.hpp"

namespace etl
{
template <class Type>
struct less
{
    constexpr auto operator()(const Type& lhs, const Type& rhs) const -> bool
    {
        return lhs < rhs;
    }
};

template <class>
class function_view;

template <class Result, class... Arguments>
class function_view<Result(Arguments...)>
{
public:
    using result_type = Result;

    function_view(function_view const& other)
    {
        if (&other == this) { return; }
        if (create_ptr_ != nullptr) { destroy_ptr_(storage_); }
        if (other.create_ptr_ != nullptr)
        {
            invoke_ptr_  = other.invoke_ptr_;
            create_ptr_  = other.create_ptr_;
            destroy_ptr_ = other.destroy_ptr_;
            create_ptr_(storage_, const_cast<etl::byte*>(other.storage_));
        }
    }

    auto operator=(function_view const& other) -> function_view&
    {
        if (&other == this) { return *this; }
        if (create_ptr_ != nullptr) { destroy_ptr_(storage_); }
        if (other.create_ptr_ != nullptr)
        {
            invoke_ptr_  = other.invoke_ptr_;
            create_ptr_  = other.create_ptr_;
            destroy_ptr_ = other.destroy_ptr_;
            create_ptr_(storage_, const_cast<etl::byte*>(other.storage_));
        }

        return *this;
    }

    ~function_view() noexcept { destroy_ptr_(storage_); }

    [[nodiscard]] auto operator()(Arguments&&... args) const -> result_type
    {
        return invoke_ptr_(const_cast<etl::byte*>(storage_),
                           etl::forward<Arguments>(args)...);  // NOLINT
    }

protected:
    template <typename Functor>
    function_view(Functor f, etl::byte* storage)
        : invoke_ptr_ {reinterpret_cast<invoke_pointer_t>(invoke<Functor>)}
        , create_ptr_ {reinterpret_cast<create_pointer_t>(create<Functor>)}
        , destroy_ptr_ {reinterpret_cast<destroy_pointer_t>(destroy<Functor>)}
        , storage_ {storage}
    {
        create_ptr_(storage_, &f);
    }

private:
    template <typename Functor>
    static auto invoke(Functor* f, Arguments&&... args) -> Result
    {
        return (*f)(etl::forward<Arguments>(args)...);
    }

    template <typename Functor>
    static auto create(Functor* destination, Functor* source) -> void
    {
        new (destination) Functor(*source);
    }

    template <typename Functor>
    static auto destroy(Functor* f) -> void
    {
        f->~Functor();
    }

    using invoke_pointer_t  = Result (*)(void*, Arguments&&...);
    using create_pointer_t  = void (*)(void*, void*);
    using destroy_pointer_t = void (*)(void*);

    invoke_pointer_t invoke_ptr_   = nullptr;
    create_pointer_t create_ptr_   = nullptr;
    destroy_pointer_t destroy_ptr_ = nullptr;

    etl::byte* storage_ = nullptr;
};

template <size_t, class>
class function;

template <size_t Capacity, class Result, class... Arguments>
class function<Capacity, Result(Arguments...)>
    : public function_view<Result(Arguments...)>
{
public:
    template <typename Functor>
    function(Functor f)
        : function_view<Result(Arguments...)> {
            etl::forward<Functor>(f),
            storage_,
        }
    {
        static_assert(sizeof(Functor) <= sizeof(storage_));
    }

private:
    etl::byte storage_[Capacity];  // NOLINT: Allow implicit conversion from
                                   // `char`, because <some valid reason>.
};

}  // namespace etl

#endif  // TAETL_FUNCTIONAL_HPP