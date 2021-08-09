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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_NOTHROW_COPY_CONSTRUCTIBLE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_NOTHROW_COPY_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/add_const.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_nothrow_constructible.hpp"

namespace etl {

/// \brief Same as copy, but uses etl::is_nothrow_constructible<T, T const&>.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined.
///
/// The behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_nothrow_copy_constructible
    : is_nothrow_constructible<T, add_lvalue_reference_t<add_const_t<T>>> {
};

template <typename T>
inline constexpr bool is_nothrow_copy_constructible_v
    = is_nothrow_copy_constructible<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_NOTHROW_COPY_CONSTRUCTIBLE_HPP