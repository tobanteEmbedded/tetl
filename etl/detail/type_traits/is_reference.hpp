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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_REFERENCE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_REFERENCE_HPP

#include "etl/detail/type_traits/bool_constant.hpp"

namespace etl {

/// \brief If T is a reference type (lvalue reference or rvalue reference),
/// provides the member constant value equal true. For any other type, value is
/// false. The behavior of a program that adds specializations for is_reference
/// or is_reference_v is undefined.
/// \group is_reference
template <typename T>
struct is_reference : false_type {
};

/// \exclude
template <typename T>
struct is_reference<T&> : true_type {
};

/// \exclude
template <typename T>
struct is_reference<T&&> : true_type {
};
/// \group is_reference
template <typename T>
inline constexpr bool is_reference_v = is_reference<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_REFERENCE_HPP