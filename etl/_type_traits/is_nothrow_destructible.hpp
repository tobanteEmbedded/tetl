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

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_destructible.hpp"

namespace etl {

namespace detail {
template <bool, typename Type>
struct is_nothrow_destructible_helper;

template <typename Type>
struct is_nothrow_destructible_helper<false, Type> : etl::false_type {
};

template <typename Type>
struct is_nothrow_destructible_helper<true, Type>
    : etl::bool_constant<noexcept(etl::declval<Type>().~Type())> {
};
} // namespace detail

/// https://en.cppreference.com/w/cpp/types/is_destructible
/// \group is_nothrow_destructible
template <typename Type>
struct is_nothrow_destructible
    : detail::is_nothrow_destructible_helper<is_destructible_v<Type>, Type> {
};

/// \exclude
template <typename Type, size_t N>
struct is_nothrow_destructible<Type[N]> : is_nothrow_destructible<Type> {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&> : true_type {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&&> : true_type {
};

/// \group is_nothrow_destructible
template <typename T>
inline constexpr bool is_nothrow_destructible_v
    = is_nothrow_destructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP