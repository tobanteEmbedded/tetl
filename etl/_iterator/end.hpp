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

#ifndef TETL_ITERATOR_END_HPP
#define TETL_ITERATOR_END_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// `C::end()` having a reasonable implementation. \group end \module Iterator
template <typename C>
constexpr auto end(C& c) -> decltype(c.end())
{
    return c.end();
}

/// \group end
template <typename C>
constexpr auto end(C const& c) -> decltype(c.end())
{
    return c.end();
}

/// \group end
template <typename T, etl::size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
    return &array[N];
}

/// \group end
template <typename C>
constexpr auto cend(C const& c) noexcept(noexcept(end(c))) -> decltype(end(c))
{
    return end(c);
}

} // namespace etl

#endif // TETL_ITERATOR_END_HPP