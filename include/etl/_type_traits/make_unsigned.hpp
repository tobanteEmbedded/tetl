// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP

namespace etl {

namespace detail {

template <typename>
struct make_unsigned;

template <>
struct make_unsigned<signed char> {
    using type = unsigned char;
};

template <>
struct make_unsigned<signed short> {
    using type = unsigned short;
};

template <>
struct make_unsigned<signed int> {
    using type = unsigned int;
};

template <>
struct make_unsigned<signed long> {
    using type = unsigned long;
};

template <>
struct make_unsigned<signed long long> {
    using type = unsigned long long;
};

template <>
struct make_unsigned<unsigned char> {
    using type = unsigned char;
};

template <>
struct make_unsigned<unsigned short> {
    using type = unsigned short;
};

template <>
struct make_unsigned<unsigned int> {
    using type = unsigned int;
};

template <>
struct make_unsigned<unsigned long> {
    using type = unsigned long;
};

template <>
struct make_unsigned<unsigned long long> {
    using type = unsigned long long;
};

} // namespace detail

/// \brief If T is an integral (except bool) or enumeration type, provides the
/// member typedef type which is the unsigned integer type corresponding to T,
/// with the same cv-qualifiers. If T is signed or unsigned char, short, int,
/// long, long long; the unsigned type from this list corresponding to T is
/// provided. The behavior of a program that adds specializations for
/// make_unsigned is undefined.
template <typename Type>
struct make_unsigned : etl::detail::make_unsigned<Type> { };

template <typename T>
using make_unsigned_t = typename make_unsigned<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP
