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

#ifndef TETL_DETAIL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP
#define TETL_DETAIL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/remove_all_extents.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

/// \brief If T is TriviallyCopyable and if any two objects of type T with the
/// same value have the same object representation, provides the member constant
/// value equal true. For any other type, value is false.
///
/// \details For the purpose of this trait, two arrays have the same value if
/// their elements have the same values, two non-union classes have the same
/// value if their direct subobjects have the same value, and two unions have
/// the same value if they have the same active member and the value of that
/// member is the same. It is implementation-defined which scalar types satisfy
/// this trait, but unsigned (until C++20) integer types that do not use padding
/// bits are guaranteed to have unique object representations. The behavior is
/// undefined if T is an incomplete type other than (possibly cv-qualified) void
/// or array of unknown bound. The behavior of a program that adds
/// specializations for has_unique_object_representations or
/// has_unique_object_representations_v is undefined.
template <typename T>
struct has_unique_object_representations
    : bool_constant<TETL_HAS_UNIQUE_OBJECT_REPRESENTATION(
          remove_cv_t<remove_all_extents_t<T>>)> {
};

template <typename T>
inline constexpr bool has_unique_object_representations_v
    = has_unique_object_representations<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP