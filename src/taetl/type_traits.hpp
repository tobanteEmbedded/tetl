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

#ifndef TAETL_TYPETRAITS_HPP
#define TAETL_TYPETRAITS_HPP

// TAETL
#include "definitions.hpp"
#include "intrinsics.hpp"

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
using true_type  = integral_constant<bool, true>;
using false_type = integral_constant<bool, false>;

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

template <class T>
using remove_const_t = typename remove_const<T>::type;

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

template <class T>
using remove_volatile_t = typename remove_volatile<T>::type;

// remove_cv
template <typename Type>
struct remove_cv
{
    typedef
        typename remove_const<typename remove_volatile<Type>::type>::type type;
};

template <class T>
using remove_cv_t = typename remove_cv<T>::type;

/**
 * @brief If T and U name the same type (taking into account const/volatile
 * qualifications), provides the member constant value equal to true. Otherwise
 * value is false.
 */
template <class T, class U>
struct is_same : false_type
{
};

template <class T>
struct is_same<T, T> : true_type
{
};

template <class T, class U>
inline constexpr bool is_same_v = is_same<T, U>::value;

/**
 * @brief Define a member typedef only if a boolean constant is true.
 */
template <class T>
struct is_void : is_same<void, typename remove_cv<T>::type>
{
};

template <class T>
inline constexpr bool is_void_v = is_void<T>::value;

/// @cond
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

/// @endcond

// is_integral
template <typename Type>
struct is_integral
    : public _is_integral_helper<typename remove_cv<Type>::type>::type
{
};

template <class T>
inline constexpr bool is_integral_v = is_integral<T>::value;

template <class T>
struct is_floating_point
    : taetl::integral_constant<
          bool, taetl::is_same<float, typename taetl::remove_cv<T>::type>::value
                    || taetl::is_same<double,
                                      typename taetl::remove_cv<T>::type>::value
                    || taetl::is_same<
                        long double, typename taetl::remove_cv<T>::type>::value>
{
};

template <class T>
inline constexpr bool is_floating_point_v = is_floating_point<T>::value;

template <class T>
struct is_null_pointer : is_same<nullptr_t, remove_cv_t<T>>
{
};

template <class T>
inline constexpr bool is_null_pointer_v = is_null_pointer<T>::value;

template <class T>
struct is_array : false_type
{
};

template <class T>
struct is_array<T[]> : true_type
{
};

template <class T, size_t N>
struct is_array<T[N]> : true_type
{
};

template <class T>
inline constexpr bool is_array_v = is_array<T>::value;

template <class T>
struct is_pointer_helper : false_type
{
};
template <class T>
struct is_pointer_helper<T*> : true_type
{
};

template <class T>
struct is_pointer : is_pointer_helper<typename remove_cv<T>::type>
{
};

template <class T>
inline constexpr bool is_pointer_v = is_pointer<T>::value;

template <class T>
struct is_class : taetl::integral_constant<bool, TAETL_IS_CLASS(T)>
{
};

template <class T>
inline constexpr bool is_class_v = is_class<T>::value;

/**
 * @brief Define a member typedef only if a boolean constant is true.
 */
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

#endif  // TAETL_TYPETRAITS_HPP