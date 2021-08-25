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

#ifndef TETL_ITERATOR_SIZE_HPP
#define TETL_ITERATOR_SIZE_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/make_signed.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Returns the size of the given container c or array array. Returns
/// c.size(), converted to the return type if necessary.
/// \group size
/// \module Iterator
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size()))
    -> decltype(c.size())
{
    return c.size();
}

/// \group size
template <typename T, size_t N>
constexpr auto size(T const (&array)[N]) noexcept -> size_t
{
    etl::ignore_unused(&array[0]);
    return N;
}

template <typename C>
constexpr auto ssize(C const& c)
    -> common_type_t<ptrdiff_t, make_signed_t<decltype(c.size())>>
{
    using R = common_type_t<ptrdiff_t, make_signed_t<decltype(c.size())>>;
    return static_cast<R>(c.size());
}

template <typename T, ptrdiff_t N>
constexpr auto ssize(T const (&array)[static_cast<size_t>(N)]) noexcept
    -> ptrdiff_t
{
    // The static_cast<size_t>(N) inside the array parameter is to keep gcc's
    // sign-conversion warnings happy. Array sizes are of type size_t which
    // triggers a signed to unsigned conversion in this case.
    etl::ignore_unused(&array[0]);
    return N;
}

} // namespace etl

#endif // TETL_ITERATOR_SIZE_HPP