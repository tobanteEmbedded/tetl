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

#ifndef TETL_DETAIL_TYPE_TRAITS_REMOVE_CV_HPP
#define TETL_DETAIL_TYPE_TRAITS_REMOVE_CV_HPP

#include "etl/_type_traits/remove_const.hpp"
#include "etl/_type_traits/remove_volatile.hpp"

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except that
/// its topmost cv-qualifiers are removed. Removes the topmost const, or the
/// topmost volatile, or both, if present.
/// \details The behavior of a program that adds specializations for any of the
/// templates described on this page is undefined.
/// \group remove_cv
template <typename Type>
struct remove_cv {
    using type = remove_const_t<remove_volatile_t<Type>>;
};

/// \group remove_cv
template <typename T>
using remove_cv_t = typename remove_cv<T>::type;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_REMOVE_CV_HPP