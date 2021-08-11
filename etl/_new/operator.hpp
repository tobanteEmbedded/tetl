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

#ifndef TETL_NEW_OPERATOR_HPP
#define TETL_NEW_OPERATOR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_warning/ignore_unused.hpp"

// Some parts of the new header are declared in the global namespace. To avoid
// ODR violations, we include the header <new> if it is available.
#if __has_include(<new>)
#include <new>
#else

/// \brief Called by the standard single-object placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] auto operator new(etl::size_t count, void* ptr) noexcept -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

/// \brief Called by the standard array form placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] auto operator new[](etl::size_t count, void* ptr) noexcept
    -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

#endif

#endif // TETL_NEW_OPERATOR_HPP