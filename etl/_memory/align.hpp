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

#ifndef TETL_MEMORY_ALIGN_HPP
#define TETL_MEMORY_ALIGN_HPP

#include "etl/_cstddef/size_t.hpp"

#include "etl/bit.hpp"
#include "etl/cstdint.hpp"

namespace etl {

/// \brief Given a pointer ptr to a buffer of size space, returns a pointer
/// aligned by the specified alignment for size number of bytes and decreases
/// space argument by the number of bytes used for alignment. The first aligned
/// address is returned.
///
/// The function modifies the pointer only if it would be possible to fit the
/// wanted number of bytes aligned by the given alignment into the buffer. If
/// the buffer is too small, the function does nothing and returns nullptr.
///
/// The behavior is undefined if alignment is not a power of two.
[[nodiscard]] inline auto align(::etl::size_t alignment, ::etl::size_t size,
    void*& ptr, ::etl::size_t& space) noexcept -> void*
{
    auto off = static_cast<::etl::size_t>(
        bit_cast<::etl::uintptr_t>(ptr) & (alignment - 1));
    if (off != 0) { off = alignment - off; }
    if (space < off || space - off < size) { return nullptr; }

    ptr = static_cast<char*>(ptr) + off;
    space -= off;
    return ptr;
}

} // namespace etl

#endif // TETL_MEMORY_ALIGN_HPP