/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_MAKE_SIGNED_HPP
#define TETL_TYPE_TRAITS_MAKE_SIGNED_HPP

namespace etl {

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
struct make_signed {
private:
    static auto make_signed_helper(signed char) -> signed char;
    static auto make_signed_helper(signed short) -> signed short;
    static auto make_signed_helper(signed int) -> signed int;
    static auto make_signed_helper(signed long) -> signed long;
    static auto make_signed_helper(signed long long) -> signed long long;

    static auto make_signed_helper(unsigned char) -> signed char;
    static auto make_signed_helper(unsigned short) -> signed short;
    static auto make_signed_helper(unsigned int) -> signed int;
    static auto make_signed_helper(unsigned long) -> signed long;
    static auto make_signed_helper(unsigned long long) -> signed long long;

public:
    using type = decltype(make_signed_helper(Type {}));
};

/// \group make_signed
template <typename T>
using make_signed_t = typename make_signed<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_MAKE_SIGNED_HPP