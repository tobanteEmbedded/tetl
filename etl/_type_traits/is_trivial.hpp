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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_TRIVIAL_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_TRIVIAL_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_trivially_copyable.hpp"
#include "etl/_type_traits/is_trivially_default_constructible.hpp"

namespace etl {

/// \brief If T is TrivialType (that is, a scalar type, a trivially copyable
/// class with a trivial default constructor, or array of such type/class,
/// possibly cv-qualified), provides the member constant value equal to true.
/// For any other type, value is false.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_trivial](https://en.cppreference.com/w/cpp/types/is_trivial)
/// \group is_trivial
template <typename T>
struct is_trivial
    : bool_constant<is_trivially_copyable_v<
                        T> and is_trivially_default_constructible_v<T>> {
};

/// \group is_trivial
template <typename T>
inline constexpr bool is_trivial_v = is_trivial<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_TRIVIAL_HPP