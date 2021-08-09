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

#ifndef TETL_DETAIL_TYPE_TRAITS_EXTENT_HPP
#define TETL_DETAIL_TYPE_TRAITS_EXTENT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

/// \brief If T is an array type, provides the member constant value equal to
/// the number of elements along the Nth dimension of the array, if N is in [0,
/// rank_v<T>). For any other type, or if T is an array of unknown bound along
/// its first dimension and N is 0, value is 0.
/// \group extent
template <typename T, unsigned N = 0>
struct extent : integral_constant<size_t, 0> {
};

/// \exclude
template <typename T>
struct extent<T[], 0> : integral_constant<size_t, 0> {
};

/// \exclude
template <typename T, unsigned N>
struct extent<T[], N> : extent<T, N - 1> {
};

/// \exclude
template <typename T, size_t I>
struct extent<T[I], 0> : integral_constant<size_t, I> {
};

/// \exclude
template <typename T, size_t I, unsigned N>
struct extent<T[I], N> : extent<T, N - 1> {
};

/// \group extent
template <typename T>
using extent_v = typename extent<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_EXTENT_HPP