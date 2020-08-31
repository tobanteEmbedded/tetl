/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

namespace etl
{
// integral_constant
template <typename Type, Type val>
struct integral_constant
{
    static constexpr Type value = val;
    using value_type            = Type;
    using type                  = integral_constant<Type, val>;
    constexpr operator value_type() const noexcept { return value; }
    constexpr auto operator()() const noexcept -> value_type { return value; }
};

using true_type  = integral_constant<bool, true>;
using false_type = integral_constant<bool, false>;

template <class...>
using void_t = void;

template <class T>
struct type_identity
{
    using type = T;
};

namespace detail
{
template <class T>
auto try_add_lvalue_reference(int) -> etl::type_identity<T&>;
template <class T>
auto try_add_lvalue_reference(...) -> etl::type_identity<T>;

template <class T>
auto try_add_rvalue_reference(int) -> etl::type_identity<T&&>;
template <class T>
auto try_add_rvalue_reference(...) -> etl::type_identity<T>;

}  // namespace detail

template <class T>
struct add_lvalue_reference : decltype(detail::try_add_lvalue_reference<T>(0))
{
};

template <class T>
struct add_rvalue_reference : decltype(detail::try_add_rvalue_reference<T>(0))
{
};

template <class T>
using add_lvalue_reference_t = typename add_lvalue_reference<T>::type;

template <class T>
using add_rvalue_reference_t = typename add_rvalue_reference<T>::type;

template <typename T>
auto declval() noexcept -> typename etl::add_rvalue_reference<T>::type;

// remove_const
template <typename Type>
struct remove_const
{
    using type = Type;
};

template <typename Type>
struct remove_const<Type const>
{
    using type = Type;
};

template <class T>
using remove_const_t = typename remove_const<T>::type;

// remove_volatile
template <typename Type>
struct remove_volatile
{
    using type = Type;
};

template <typename Type>
struct remove_volatile<Type volatile>
{
    using type = Type;
};

template <class T>
using remove_volatile_t = typename remove_volatile<T>::type;

// remove_cv
template <typename Type>
struct remove_cv
{
    using type =
        typename remove_const<typename remove_volatile<Type>::type>::type;
};

template <class T>
using remove_cv_t = typename remove_cv<T>::type;

template <class T>
struct remove_reference
{
    using type = T;
};

template <class T>
struct remove_reference<T&>
{
    using type = T;
};

template <class T>
struct remove_reference<T&&>
{
    using type = T;
};

template <class T>
using remove_reference_t = typename remove_reference<T>::type;

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
namespace detail
{
template <typename>
struct is_integral_helper : public false_type
{
};

template <>
struct is_integral_helper<bool> : public true_type
{
};

template <>
struct is_integral_helper<char> : public true_type
{
};

template <>
struct is_integral_helper<signed char> : public true_type
{
};

template <>
struct is_integral_helper<unsigned char> : public true_type
{
};

template <>
struct is_integral_helper<char16_t> : public true_type
{
};

template <>
struct is_integral_helper<char32_t> : public true_type
{
};

template <>
struct is_integral_helper<short> : public true_type
{
};

template <>
struct is_integral_helper<unsigned short> : public true_type
{
};

template <>
struct is_integral_helper<int> : public true_type
{
};

template <>
struct is_integral_helper<unsigned int> : public true_type
{
};

template <>
struct is_integral_helper<long> : public true_type
{
};

template <>
struct is_integral_helper<unsigned long> : public true_type
{
};

template <>
struct is_integral_helper<long long> : public true_type
{
};

template <>
struct is_integral_helper<unsigned long long> : public true_type
{
};
}  // namespace detail

/// @endcond

// is_integral
template <typename Type>
struct is_integral
    : public detail::is_integral_helper<typename remove_cv<Type>::type>::type
{
};

template <class T>
inline constexpr bool is_integral_v = is_integral<T>::value;

/**
 * @brief If T is an integral (except bool) or enumeration type, provides the
 * member typedef type which is the unsigned integer type corresponding to T,
 * with the same cv-qualifiers. If T is signed or unsigned char, short, int,
 * long, long long; the unsigned type from this list corresponding to T is
 * provided. The behavior of a program that adds specializations for
 * make_unsigned is undefined.
 */
template <typename>
struct make_unsigned;

template <>
struct make_unsigned<signed char>
{
    using type = unsigned char;
};

template <>
struct make_unsigned<signed short>
{
    using type = unsigned short;
};

template <>
struct make_unsigned<signed int>
{
    using type = unsigned int;
};

template <>
struct make_unsigned<signed long>
{
    using type = unsigned long;
};

template <>
struct make_unsigned<signed long long>
{
    using type = unsigned long long;
};

template <>
struct make_unsigned<unsigned char>
{
    using type = unsigned char;
};

template <>
struct make_unsigned<unsigned short>
{
    using type = unsigned short;
};

template <>
struct make_unsigned<unsigned int>
{
    using type = unsigned int;
};

template <>
struct make_unsigned<unsigned long>
{
    using type = unsigned long;
};

template <>
struct make_unsigned<unsigned long long>
{
    using type = unsigned long long;
};

template <class T>
using make_unsigned_t = typename make_unsigned<T>::type;

template <class T>
struct is_floating_point
    : etl::integral_constant<
          bool,
          etl::is_same<float, typename etl::remove_cv<T>::type>::value
              || etl::is_same<double, typename etl::remove_cv<T>::type>::value
              || etl::is_same<long double,
                              typename etl::remove_cv<T>::type>::value>
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

namespace detail
{
template <class T>
struct is_pointer_helper : etl::false_type
{
};
template <class T>
struct is_pointer_helper<T*> : etl::true_type
{
};
}  // namespace detail

template <class T>
struct is_pointer : detail::is_pointer_helper<typename remove_cv<T>::type>
{
};

template <class T>
inline constexpr bool is_pointer_v = is_pointer<T>::value;

template <class T>
struct is_class : etl::integral_constant<bool, TAETL_IS_CLASS(T)>
{
};

template <class T>
inline constexpr bool is_class_v = is_class<T>::value;

template <class T>
struct is_enum : etl::integral_constant<bool, TAETL_IS_ENUM(T)>
{
};

template <class T>
inline constexpr bool is_enum_v = is_enum<T>::value;

template <class T>
struct is_union : etl::integral_constant<bool, TAETL_IS_UNION(T)>
{
};

template <class T>
inline constexpr bool is_union_v = is_union<T>::value;

/**
 * @brief If T is an arithmetic type (that is, an integral type or a
 * floating-point type) or a cv-qualified version thereof, provides the member
 * constant value equal true. For any other type, value is false. The behavior
 * of a program that adds specializations for is_arithmetic or is_arithmetic_v
 * (since C++17) is undefined.
 */
template <class T>
struct is_arithmetic
    : etl::integral_constant<bool, etl::is_integral<T>::value
                                       || etl::is_floating_point<T>::value>
{
};

template <class T>
inline constexpr bool is_arithmetic_v = is_arithmetic<T>::value;

namespace detail
{
template <class, class T, class... Args>
struct is_constructible_helper : etl::false_type
{
};

template <class T, class... Args>
struct is_constructible_helper<void_t<decltype(T(declval<Args>()...))>, T,
                               Args...> : etl::true_type
{
};
}  // namespace detail

template <class T, class... Args>
using is_constructible = detail::is_constructible_helper<void_t<>, T, Args...>;

template <class T, class... Args>
inline constexpr bool is_constructible_v = is_constructible<T, Args...>::value;

namespace detail
{
template <typename T, bool = etl::is_arithmetic<T>::value>
struct is_unsigned : etl::integral_constant<bool, T(0) < T(-1)>
{
};

template <typename T>
struct is_unsigned<T, false> : etl::false_type
{
};
}  // namespace detail

/**
 * @brief If T is an arithmetic type, provides the member constant value equal
 * to true if T(0) < T(-1): this results in true for the unsigned integer types
 * and the type bool and in false for the signed integer types and the
 * floating-point types. For any other type, value is false. The behavior of a
 * program that adds specializations for is_unsigned or is_unsigned_v (since
 * C++17) is undefined.
 */
template <typename T>
struct is_unsigned : detail::is_unsigned<T>::type
{
};

template <class T>
inline constexpr bool is_unsigned_v = is_unsigned<T>::value;

/**
 * @brief Provides member typedef type, which is defined as T if B is true at
 * compile time, or as F if B is false.
 */
template <bool B, class T, class F>
struct conditional
{
    using type = T;
};

template <class T, class F>
struct conditional<false, T, F>
{
    using type = F;
};

template <bool B, class T, class F>
using conditional_t = typename conditional<B, T, F>::type;

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
    using type = Type;
};

template <bool B, class T = void>
using enable_if_t = typename enable_if<B, T>::type;

/**
 * @brief If Type is an array type, provides the member constant value equal to
 * the number of dimensions of the array. For any other type, value is 0. The
 * behavior of a program that adds specializations for rank or rank_v is
 * undefined.
 */
template <class T>
struct rank : public etl::integral_constant<etl::size_t, 0>
{
};

template <class T>
struct rank<T[]>
    : public etl::integral_constant<etl::size_t, rank<T>::value + 1>
{
};

template <class T, etl::size_t N>
struct rank<T[N]>
    : public etl::integral_constant<etl::size_t, rank<T>::value + 1>
{
};

template <class Type>
inline constexpr etl::size_t rank_v = rank<Type>::value;
}  // namespace etl

#endif  // TAETL_TYPETRAITS_HPP