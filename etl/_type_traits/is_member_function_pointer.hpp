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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

namespace detail {
template <typename T>
struct is_member_function_pointer_helper : ::etl::false_type {
};

template <typename T, typename U>
struct is_member_function_pointer_helper<T U::*> : ::etl::is_function<T> {
};

} // namespace detail

/// \brief Checks whether T is a non-static member function pointer. Provides
/// the member constant value which is equal to true, if T is a non-static
/// member function pointer type. Otherwise, value is equal to false.
template <typename T>
struct is_member_function_pointer
    : detail::is_member_function_pointer_helper<remove_cv_t<T>> {
};

template <typename T>
inline constexpr bool is_member_function_pointer_v
    = is_member_function_pointer<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_MEMBER_FUNCTION_POINTER_HPP