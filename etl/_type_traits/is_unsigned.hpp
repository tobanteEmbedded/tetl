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

#ifndef TETL_TYPE_TRAITS_IS_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_IS_UNSIGNED_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl {

namespace detail {
template <typename T, bool = etl::is_arithmetic_v<T>>
struct is_unsigned : etl::bool_constant<T(0) < T(-1)> {
};

template <typename T>
struct is_unsigned<T, false> : etl::false_type {
};
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(0) < T(-1): this results in true for the unsigned integer types
/// and the type bool and in false for the signed integer types and the
/// floating-point types. For any other type, value is false. The behavior of a
/// program that adds specializations for is_unsigned or is_unsigned_v (since
/// C++17) is undefined.
template <typename T>
struct is_unsigned : detail::is_unsigned<T>::type {
};

template <typename T>
inline constexpr bool is_unsigned_v = is_unsigned<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNSIGNED_HPP