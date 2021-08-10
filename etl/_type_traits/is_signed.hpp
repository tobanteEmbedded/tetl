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

#ifndef TETL_TYPE_TRAITS_IS_SIGNED_HPP
#define TETL_TYPE_TRAITS_IS_SIGNED_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl {

namespace detail {
template <typename T, bool = ::etl::is_arithmetic_v<T>>
struct is_signed : ::etl::bool_constant<T(-1) < T(0)> {
};

template <typename T>
struct is_signed<T, false> : ::etl::false_type {
};
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(-1) < T(0): this results in true for the floating-point types
/// and the signed integer types, and in false for the unsigned integer types
/// and the type bool. For any other type, value is false.
template <typename T>
struct is_signed : detail::is_signed<T>::type {
};

template <typename T>
inline constexpr bool is_signed_v = is_signed<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SIGNED_HPP