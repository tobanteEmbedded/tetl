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

#ifndef TETL_TYPE_TRAITS_META_HPP
#define TETL_TYPE_TRAITS_META_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl::detail {

template <typename...>
struct meta_or;

template <>
struct meta_or<> : false_type {
};

template <typename B1>
struct meta_or<B1> : B1 {
};

template <typename B1, typename B2>
struct meta_or<B1, B2> : conditional<B1::value, B1, B2>::type {
};

template <typename B1, typename B2, typename B3, typename... BRest>
struct meta_or<B1, B2, B3, BRest...>
    : conditional<B1::value, B1, meta_or<B2, B3, BRest...>>::type {
};

template <typename... BRest>
inline constexpr bool meta_or_v = meta_or<BRest...>::value;

template <typename...>
struct meta_and;

template <>
struct meta_and<> : true_type {
};

template <typename B1>
struct meta_and<B1> : B1 {
};

template <typename B1, typename B2>
struct meta_and<B1, B2> : conditional<B1::value, B2, B1>::type {
};

template <typename B1, typename B2, typename B3, typename... BRest>
struct meta_and<B1, B2, B3, BRest...>
    : conditional<B1::value, meta_and<B2, B3, BRest...>, B1>::type {
};

template <typename... BRest>
inline constexpr bool meta_and_v = meta_and<BRest...>::value;

template <typename P>
struct meta_not : bool_constant<!bool(P::value)> {
};

} // namespace etl::detail

#endif // TETL_TYPE_TRAITS_META_HPP