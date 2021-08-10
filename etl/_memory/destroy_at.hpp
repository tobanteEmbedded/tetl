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

#ifndef TETL_MEMORY_DESTROY_AT_HPP
#define TETL_MEMORY_DESTROY_AT_HPP

#include "etl/_memory/addressof.hpp"
#include "etl/_type_traits/is_array.hpp"

namespace etl {

/// \brief If T is not an array type, calls the destructor of the object pointed
/// to by p, as if by p->~T(). If T is an array type, recursively destroys
/// elements of *p in order, as if by calling destroy(begin(*p),
/// end(*p)).
/// \group destroy
template <typename T>
constexpr auto destroy_at(T* p) -> void
{
    if constexpr (etl::is_array_v<T>) {
        for (auto& elem : *p) { etl::destroy_at(etl::addressof(elem)); }
    } else {
        p->~T();
    }
}

} // namespace etl

#endif // TETL_MEMORY_DESTROY_AT_HPP