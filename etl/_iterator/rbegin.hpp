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

#ifndef TETL_DETAIL_ITERATOR_RBEGIN_HPP
#define TETL_DETAIL_ITERATOR_RBEGIN_HPP

#include "etl/_iterator/end.hpp"

namespace etl {

template <typename Iter>
struct reverse_iterator;

/// \brief Returns an iterator to the reverse-beginning of the given container.
/// \group rbegin
/// \module Iterator
template <typename Container>
constexpr auto rbegin(Container& c) -> decltype(c.rbegin())
{
    return c.rbegin();
}

/// \group rbegin
template <typename Container>
constexpr auto rbegin(Container const& c) -> decltype(c.rbegin())
{
    return c.rbegin();
}

/// \group rbegin
template <typename T, size_t N>
constexpr auto rbegin(T (&array)[N]) -> reverse_iterator<T*>
{
    return reverse_iterator<T*>(end(array));
}

/// \group rbegin
template <typename Container>
constexpr auto crbegin(Container const& c) -> decltype(rbegin(c))
{
    return rbegin(c);
}

} // namespace etl

#endif // TETL_DETAIL_ITERATOR_RBEGIN_HPP