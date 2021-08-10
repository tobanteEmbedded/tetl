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

#ifndef TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP

namespace etl {

namespace detail {
template <typename>
struct make_unsigned_helper;

template <>
struct make_unsigned_helper<signed char> {
    using type = unsigned char;
};

template <>
struct make_unsigned_helper<signed short> {
    using type = unsigned short;
};

template <>
struct make_unsigned_helper<signed int> {
    using type = unsigned int;
};

template <>
struct make_unsigned_helper<signed long> {
    using type = unsigned long;
};

template <>
struct make_unsigned_helper<signed long long> {
    using type = unsigned long long;
};

template <>
struct make_unsigned_helper<unsigned char> {
    using type = unsigned char;
};

template <>
struct make_unsigned_helper<unsigned short> {
    using type = unsigned short;
};

template <>
struct make_unsigned_helper<unsigned int> {
    using type = unsigned int;
};

template <>
struct make_unsigned_helper<unsigned long> {
    using type = unsigned long;
};

template <>
struct make_unsigned_helper<unsigned long long> {
    using type = unsigned long long;
};

} // namespace detail

/// \brief If T is an integral (except bool) or enumeration type, provides the
/// member typedef type which is the unsigned integer type corresponding to T,
/// with the same cv-qualifiers. If T is signed or unsigned char, short, int,
/// long, long long; the unsigned type from this list corresponding to T is
/// provided. The behavior of a program that adds specializations for
/// make_unsigned is undefined.
/// \group make_unsigned
template <typename Type>
struct make_unsigned : detail::make_unsigned_helper<Type> {
};

/// \group make_unsigned
template <typename T>
using make_unsigned_t = typename make_unsigned<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP