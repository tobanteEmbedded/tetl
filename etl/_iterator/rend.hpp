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

#ifndef TETL_DETAIL_ITERATOR_REND_HPP
#define TETL_DETAIL_ITERATOR_REND_HPP

#include "etl/_iterator/begin.hpp"

namespace etl {

template <typename Iter>
struct reverse_iterator;

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
/// \module Iterator
template <typename Container>
constexpr auto rend(Container& c) -> decltype(c.rend())
{
    return c.rend();
}

/// \group rend
template <typename Container>
constexpr auto rend(Container const& c) -> decltype(c.rend())
{
    return c.rend();
}

/// \group rend
template <typename T, size_t N>
constexpr auto rend(T (&array)[N]) -> reverse_iterator<T*>
{
    return reverse_iterator<T*>(begin(array));
}

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
template <typename Container>
constexpr auto crend(Container const& c) -> decltype(rend(c))
{
    return rend(c);
}

} // namespace etl

#endif // TETL_DETAIL_ITERATOR_REND_HPP