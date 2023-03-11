/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
template <typename Type>
struct make_signed : detail::make_signed_helper<Type> { };

template <typename T>
using make_signed_t = typename make_signed<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_SIGNED_HPP
