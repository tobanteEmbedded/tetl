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
class function;
template <class Result, class... Arguments>
class function<Result(Arguments...)>
{
public:
    using result_type = Result;

    template <typename Functor>
    function(Functor f)
        : invokePtr {reinterpret_cast<invokePtr_t>(invoke<Functor>)}
        , createPtr {reinterpret_cast<createPtr_t>(create<Functor>)}
        , destroyPtr {reinterpret_cast<destroyPtr_t>(destroy<Functor>)}
    {
        static_assert(sizeof(Functor) <= sizeof(storage_));
        createPtr(storage_.data(), &f);
    }

    function(function const& other)
    {
        if (&other == this) { return; }
        if (createPtr != nullptr) { destroyPtr(storage_.data()); }
        if (other.createPtr != nullptr)
        {
            invokePtr  = other.invokePtr;
            createPtr  = other.createPtr;
            destroyPtr = other.destroyPtr;
            createPtr(storage_.data(),
                      const_cast<etl::byte*>(other.storage_.data()));
        }
    }

    auto operator=(function const& other) -> function&
    {
        if (&other == this) { return *this; }
        if (createPtr != nullptr) { destroyPtr(storage_.data()); }
        if (other.createPtr != nullptr)
        {
            invokePtr  = other.invokePtr;
            createPtr  = other.createPtr;
            destroyPtr = other.destroyPtr;
            createPtr(storage_.data(),
                      const_cast<etl::byte*>(other.storage_.data()));
        }

        return *this;
    }

    ~function() noexcept { destroyPtr(storage_.data()); }

    [[nodiscard]] auto operator()(Arguments&&... args) const -> result_type
    {
        return invokePtr(const_cast<etl::byte*>(storage_.data()),
                         etl::forward<Arguments>(args)...);
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

    using invokePtr_t  = Result (*)(void*, Arguments&&...);
    using createPtr_t  = void (*)(void*, void*);
    using destroyPtr_t = void (*)(void*);

    invokePtr_t invokePtr   = nullptr;
    createPtr_t createPtr   = nullptr;
    destroyPtr_t destroyPtr = nullptr;

    etl::array<etl::byte, 32> storage_ {};
};

}  // namespace etl

#endif  // TAETL_FUNCTIONAL_HPP