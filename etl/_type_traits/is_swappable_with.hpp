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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

namespace detail {
template <typename T, typename U, typename = void>
struct is_swappable_with_impl : false_type {
};

template <typename T, typename U>
struct is_swappable_with_impl<T, U,
    void_t<decltype(swap(declval<T>(), declval<U>()))>> : true_type {
};

} // namespace detail

/// \brief If the expressions swap(etl::declval<T>(), etl::declval<U>()) and
/// swap(etl::declval<U>(), etl::declval<T>()) are both well-formed in
/// unevaluated context after using etl::swap; provides the member constant
/// value equal true. Otherwise, value is false. Access checks are performed as
/// if from a context unrelated to either type.
template <typename T, typename U>
struct is_swappable_with
    : bool_constant<conjunction_v<detail::is_swappable_with_impl<T, U>,
          detail::is_swappable_with_impl<U, T>>> {
};

template <typename T, typename U>
inline constexpr bool is_swappable_with_v = is_swappable_with<T, U>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_WITH_HPP