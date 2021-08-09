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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP

#include "etl/detail/type_traits/bool_constant.hpp"
#include "etl/detail/type_traits/is_convertible.hpp"
#include "etl/detail/type_traits/is_enum.hpp"
#include "etl/detail/type_traits/underlying_type.hpp"

namespace etl {

template <typename T, bool = is_enum_v<T>>
struct is_scoped_enum : false_type {
};

template <typename T>
struct is_scoped_enum<T, true>
    : bool_constant<!is_convertible_v<T, underlying_type_t<T>>> {
};

/// \brief Checks whether T is an scoped enumeration type. Provides the member
/// constant value which is equal to true, if T is an scoped enumeration type.
/// Otherwise, value is equal to false. The behavior of a program that adds
/// specializations for is_scoped_enum or is_scoped_enum_v is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_scoped_enum](https://en.cppreference.com/w/cpp/types/is_scoped_enum)
template <typename T>
inline constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_SCOPED_ENUM_HPP