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

#ifndef TETL_MEMORY_CONSTRUCT_AT_HPP
#define TETL_MEMORY_CONSTRUCT_AT_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Creates a T object initialized with arguments args... at given
/// address p.
template <typename T, typename... Args,
    typename = decltype(::new (declval<void*>()) T(declval<Args>()...))>
[[nodiscard]] constexpr auto construct_at(T* p, Args&&... args) -> T*
{
    TETL_ASSERT(p != nullptr);
    return ::new (static_cast<void*>(p)) T(::etl::forward<Args>(args)...);
}

} // namespace etl

#endif // TETL_MEMORY_CONSTRUCT_AT_HPP