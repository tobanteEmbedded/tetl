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

#ifndef TETL_MEMORY_DEFAULT_DELETE_HPP
#define TETL_MEMORY_DEFAULT_DELETE_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/is_void.hpp"

namespace etl {

template <typename T>
struct default_delete {
    constexpr default_delete() noexcept = default;

    template <typename U, TETL_REQUIRES_((etl::is_convertible_v<U*, T*>))>
    default_delete(default_delete<U> const& /*unused*/) noexcept
    {
    }

    auto operator()(T* ptr) const noexcept -> void { delete ptr; }

private:
    static_assert(!is_function_v<T>);
    static_assert(!is_void_v<T>);
    static_assert(sizeof(T));
};

template <typename T>
struct default_delete<T[]> {
    constexpr default_delete() noexcept = default;

    template <typename U,
        enable_if_t<is_convertible_v<U (*)[], T (*)[]>, bool> = true>
    default_delete(default_delete<U[]> const& /*unused*/) noexcept
    {
    }

    template <typename U>
    auto operator()(U* ptr) const noexcept
        -> enable_if_t<is_convertible_v<U (*)[], T (*)[]>, void>
    {
        delete[] ptr;
    }

private:
    static_assert(sizeof(T));
    static_assert(not is_void_v<T>);
};

} // namespace etl

#endif // TETL_MEMORY_DEFAULT_DELETE_HPP