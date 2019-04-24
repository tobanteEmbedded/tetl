/*
Copyright (c) 2019, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_TYPETRAITS_H
#define TAETL_TYPETRAITS_H

// TAETL
#include "definitions.h"

namespace taetl
{
// integral_constant
template <typename Type, Type val>
struct integral_constant
{
    static constexpr Type value = val;
    typedef Type value_type;
    typedef integral_constant<Type, val> type;
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; }
};

template <typename Type, Type val>
constexpr Type integral_constant<Type, val>::value;

typedef integral_constant<bool, true> true_type;
typedef integral_constant<bool, false> false_type;

// remove_const
template <typename Type>
struct remove_const
{
    typedef Type type;
};

template <typename Type>
struct remove_const<Type const>
{
    typedef Type type;
};

// remove_volatile
template <typename Type>
struct remove_volatile
{
    typedef Type type;
};

template <typename Type>
struct remove_volatile<Type volatile>
{
    typedef Type type;
};

// remove_cv
template <typename Type>
struct remove_cv
{
    typedef
        typename remove_const<typename remove_volatile<Type>::type>::type type;
};

template <typename>
struct _is_integral_helper : public false_type
{
};

template <>
struct _is_integral_helper<bool> : public true_type
{
};

template <>
struct _is_integral_helper<char> : public true_type
{
};

template <>
struct _is_integral_helper<signed char> : public true_type
{
};

template <>
struct _is_integral_helper<unsigned char> : public true_type
{
};

template <>
struct _is_integral_helper<char16_t> : public true_type
{
};

template <>
struct _is_integral_helper<char32_t> : public true_type
{
};

template <>
struct _is_integral_helper<short> : public true_type
{
};

template <>
struct _is_integral_helper<unsigned short> : public true_type
{
};

template <>
struct _is_integral_helper<int> : public true_type
{
};

template <>
struct _is_integral_helper<unsigned int> : public true_type
{
};

template <>
struct _is_integral_helper<long> : public true_type
{
};

template <>
struct _is_integral_helper<unsigned long> : public true_type
{
};

template <>
struct _is_integral_helper<long long> : public true_type
{
};

template <>
struct _is_integral_helper<unsigned long long> : public true_type
{
};

// is_integral
template <typename Type>
struct is_integral
    : public _is_integral_helper<typename remove_cv<Type>::type>::type
{
};

// Primary template.
// Define a member typedef @c type only if a boolean constant is true.
template <bool, typename Type = void>
struct enable_if
{
};

// Partial specialization for true.
template <typename Type>
struct enable_if<true, Type>
{
    typedef Type type;
};

}  // namespace taetl

#endif  // TAETL_TYPETRAITS_H