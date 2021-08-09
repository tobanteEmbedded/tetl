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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_ARRAY_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_ARRAY_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief Checks whether T is an array type. Provides the member constant value
/// which is equal to true, if T is an array type. Otherwise, value is equal to
/// false.
/// \details The behavior of a program that adds specializations for is_array or
/// is_array_v is undefined.
/// \group is_array
template <typename T>
struct is_array : false_type {
};

/// \exclude
template <typename T>
struct is_array<T[]> : true_type {
};

/// \exclude
template <typename T, size_t N>
struct is_array<T[N]> : true_type {
};

/// \group is_array
template <typename T>
inline constexpr bool is_array_v = is_array<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_ARRAY_HPP