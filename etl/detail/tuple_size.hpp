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

#ifndef TAETL_TUPLE_SIZE_HPP
#define TAETL_TUPLE_SIZE_HPP

#include "etl/type_traits.hpp"

namespace etl
{
// class template tuple
template <typename First, typename... Rest>
struct tuple;

template <typename T>
struct tuple_size; /*undefined*/

template <typename... Types>
struct tuple_size<etl::tuple<Types...>>
    : etl::integral_constant<etl::size_t, sizeof...(Types)>
{
};

template <typename T>
struct tuple_size<const T>
    : etl::integral_constant<etl::size_t, tuple_size<T>::value>
{
};

template <typename T>
struct tuple_size<volatile T>
    : etl::integral_constant<etl::size_t, tuple_size<T>::value>
{
};

template <typename T>
struct tuple_size<const volatile T>
    : etl::integral_constant<etl::size_t, tuple_size<T>::value>
{
};

template <typename T>
inline constexpr etl::size_t tuple_size_v = tuple_size<T>::value;

template <size_t I, typename T>
struct tuple_element;

template <size_t I, typename T>
using tuple_element_t = typename tuple_element<I, T>::type;

}  // namespace etl

#endif  // TAETL_TUPLE_SIZE_HPP