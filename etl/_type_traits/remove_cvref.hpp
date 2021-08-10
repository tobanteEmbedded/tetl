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

#ifndef TETL_TYPE_TRAITS_REMOVE_CVREF_HPP
#define TETL_TYPE_TRAITS_REMOVE_CVREF_HPP

#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_type_traits/remove_reference.hpp"

namespace etl {

/// \brief If the type T is a reference type, provides the member typedef type
/// which is the type referred to by T with its topmost cv-qualifiers removed.
/// Otherwise type is T with its topmost cv-qualifiers removed.
///
/// \details The behavior of a program that adds specializations for
/// remove_cvref is undefined.
/// \group remove_cvref
template <typename T>
struct remove_cvref {
    using type = remove_cv_t<remove_reference_t<T>>;
};

/// \group remove_cvref
template <typename T>
using remove_cvref_t = typename remove_cvref<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_CVREF_HPP