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

#ifndef TETL_TYPE_TRAITS_MAKE_SIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_SIGNED_HPP

namespace etl {

namespace detail {
template <typename>
struct make_signed_helper;

template <>
struct make_signed_helper<signed char> {
    using type = signed char;
};

template <>
struct make_signed_helper<signed short> {
    using type = signed short;
};

template <>
struct make_signed_helper<signed int> {
    using type = signed int;
};

template <>
struct make_signed_helper<signed long> {
    using type = signed long;
};

template <>
struct make_signed_helper<signed long long> {
    using type = signed long long;
};

template <>
struct make_signed_helper<unsigned char> {
    using type = signed char;
};

template <>
struct make_signed_helper<unsigned short> {
    using type = signed short;
};

template <>
struct make_signed_helper<unsigned int> {
    using type = signed int;
};

template <>
struct make_signed_helper<unsigned long> {
    using type = signed long;
};

template <>
struct make_signed_helper<unsigned long long> {
    using type = signed long long;
};

} // namespace detail

/// \brief If T is an integral (except bool) or enumeration type, provides the
/// member typedef type which is the unsigned integer type corresponding to T,
/// with the same cv-qualifiers. If T is signed or unsigned char, short, int,
/// long, long long; the unsigned type from this list corresponding to T is
/// provided. The behavior of a program that adds specializations for
/// make_signed is undefined.
///
/// ```
/// // Convert an unsigned int to signed int
/// static_assert(is_same_v<make_signed_t<unsigned>, int>);
/// ```
/// \group make_signed
template <typename Type>
struct make_signed : detail::make_signed_helper<Type> {
};

/// \group make_signed
template <typename T>
using make_signed_t = typename make_signed<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_SIGNED_HPP