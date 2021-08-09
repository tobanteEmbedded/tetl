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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_ARITHMETIC_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_ARITHMETIC_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief If T is an arithmetic type (that is, an integral type or a
/// floating-point type) or a cv-qualified version thereof, provides the member
/// constant value equal true. For any other type, value is false. The behavior
/// of a program that adds specializations for is_arithmetic or is_arithmetic_v
/// (since C++17) is undefined.
template <typename T>
struct is_arithmetic
    : bool_constant<is_integral_v<T> || is_floating_point_v<T>> {
};

template <typename T>
inline constexpr bool is_arithmetic_v = is_arithmetic<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_ARITHMETIC_HPP