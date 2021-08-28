/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP

namespace etl {

/// \brief If T is an integral (except bool) or enumeration type, provides the
/// member typedef type which is the unsigned integer type corresponding to T,
/// with the same cv-qualifiers. If T is signed or unsigned char, short, int,
/// long, long long; the unsigned type from this list corresponding to T is
/// provided. The behavior of a program that adds specializations for
/// make_unsigned is undefined.
/// \group make_unsigned
template <typename Type>
struct make_unsigned {
private:
    static auto make_unsigned_helper(signed char) -> unsigned char;
    static auto make_unsigned_helper(signed short) -> unsigned short;
    static auto make_unsigned_helper(signed int) -> unsigned int;
    static auto make_unsigned_helper(signed long) -> unsigned long;
    static auto make_unsigned_helper(signed long long) -> unsigned long long;

    static auto make_unsigned_helper(unsigned char) -> unsigned char;
    static auto make_unsigned_helper(unsigned short) -> unsigned short;
    static auto make_unsigned_helper(unsigned int) -> unsigned int;
    static auto make_unsigned_helper(unsigned long) -> unsigned long;
    static auto make_unsigned_helper(unsigned long long) -> unsigned long long;

public:
    using type = decltype(make_unsigned_helper(Type {}));
};

/// \group make_unsigned
template <typename T>
using make_unsigned_t = typename make_unsigned<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_UNSIGNED_HPP