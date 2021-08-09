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

#ifndef TETL_DETAIL_TYPE_TRAITS_REMOVE_EXTENT_HPP
#define TETL_DETAIL_TYPE_TRAITS_REMOVE_EXTENT_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief If T is an array of some type X, provides the member typedef type
/// equal to X, otherwise type is T. Note that if T is a multidimensional array,
/// only the first dimension is removed. The behavior of a program that adds
/// specializations for remove_extent is undefined.
/// \group remove_extent
template <typename T>
struct remove_extent {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_extent<T[]> {
    using type = T;
};

/// \exclude
template <typename T, ::etl::size_t N>
struct remove_extent<T[N]> {
    using type = T;
};

/// \group remove_extent
template <typename T>
using remove_extent_t = typename ::etl::remove_extent<T>::type;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_REMOVE_EXTENT_HPP