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

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_assignable.hpp"

namespace etl {

namespace detail {
template <typename T, typename U>
struct is_nothrow_assignable_helper
    : etl::bool_constant<noexcept(etl::declval<T>() = etl::declval<U>())> {
};
} // namespace detail

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_nothrow_assignable
    : bool_constant<
          is_assignable_v<T,
              U> && detail::is_nothrow_assignable_helper<T, U>::value> {
};

template <typename T, typename U>
inline constexpr bool is_nothrow_assignable_v
    = is_nothrow_assignable<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP