// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_MAKE_SIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_SIGNED_HPP

namespace etl {

namespace detail {

template <typename>
struct make_signed;

template <>
struct make_signed<signed char> {
    using type = signed char;
};

template <>
struct make_signed<signed short> {
    using type = signed short;
};

template <>
struct make_signed<signed int> {
    using type = signed int;
};

template <>
struct make_signed<signed long> {
    using type = signed long;
};

template <>
struct make_signed<signed long long> {
    using type = signed long long;
};

template <>
struct make_signed<unsigned char> {
    using type = signed char;
};

template <>
struct make_signed<unsigned short> {
    using type = signed short;
};

template <>
struct make_signed<unsigned int> {
    using type = signed int;
};

template <>
struct make_signed<unsigned long> {
    using type = signed long;
};

template <>
struct make_signed<unsigned long long> {
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
struct make_signed : etl::detail::make_signed<Type> { };

template <typename T>
using make_signed_t = typename make_signed<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_SIGNED_HPP
