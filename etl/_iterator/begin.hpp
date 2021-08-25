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

#ifndef TETL_ITERATOR_BEGIN_HPP
#define TETL_ITERATOR_BEGIN_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on `C::begin()` having a reasonable
/// implementation. Returns exactly c.begin(), which is typically an iterator to
/// the beginning of the sequence represented by c. If C is a standard
/// Container, this returns `C::iterator` when c is not const-qualified, and
/// `C::const_iterator` otherwise. Custom overloads of begin may be provided for
/// classes that do not expose a suitable begin() member function, yet can be
/// iterated. \group begin \module Iterator
template <typename C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
    return c.begin();
}

/// \group begin
template <typename C>
constexpr auto begin(C const& c) -> decltype(c.begin())
{
    return c.begin();
}

/// \group begin
template <typename T, etl::size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

/// \group begin
template <typename C>
constexpr auto cbegin(C const& c) noexcept(noexcept(begin(c)))
    -> decltype(begin(c))
{
    return begin(c);
}

} // namespace etl

#endif // TETL_ITERATOR_BEGIN_HPP