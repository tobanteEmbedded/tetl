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

#ifndef TETL_TYPE_TRAITS_IS_FUNCTION_HPP
#define TETL_TYPE_TRAITS_IS_FUNCTION_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_const.hpp"
#include "etl/_type_traits/is_reference.hpp"

namespace etl {

/// \brief Checks whether T is a function type. Types like etl::function,
/// lambdas, classes with overloaded operator() and pointers to functions don't
/// count as function types. Provides the member constant value which is equal
/// to true, if T is a function type. Otherwise, value is equal to false.
///
/// \details The behavior of a program that adds specializations for is_function
/// or is_function_v is undefined.
/// \group is_function
template <typename T>
struct is_function : bool_constant<!is_const_v<T const> && !is_reference_v<T>> {
};

/// \group is_function
template <typename T>
inline constexpr bool is_function_v = is_function<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_FUNCTION_HPP