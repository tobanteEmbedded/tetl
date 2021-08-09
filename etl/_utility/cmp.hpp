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

#ifndef TETL_DETAIL_UTILITY_CMP_HPP
#define TETL_DETAIL_UTILITY_CMP_HPP

#include "etl/limits.hpp"

#include "etl/_concepts/requires.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/is_signed.hpp"
#include "etl/_type_traits/make_unsigned.hpp"

namespace etl {

namespace detail {
// clang-format off
template <typename T>
struct is_integer_and_not_char
    : bool_constant<
        is_integral_v<T>
        && (!is_same_v<T, bool>
        && !is_same_v<T, char>
        && !is_same_v<T, char16_t>
        && !is_same_v<T, char32_t>
        && !is_same_v<T, wchar_t>)>
{
};

// clang-format on

template <typename T>
inline constexpr auto int_and_not_char_v = is_integer_and_not_char<T>::value;

} // namespace detail

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_equal(T t, U u) noexcept -> bool
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;

    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>) {
        return t == u;
    } else if constexpr (etl::is_signed_v<T>) {
        return t < 0 ? false : UT(t) == u;
    } else {
        return u < 0 ? false : t == UU(u);
    }
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_not_equal(T t, U u) noexcept -> bool
{
    return !cmp_equal(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_less(T t, U u) noexcept -> bool
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;
    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>) {
        return t < u;
    } else if constexpr (etl::is_signed_v<T>) {
        return t < 0 ? true : UT(t) < u;
    } else {
        return u < 0 ? false : t < UU(u);
    }
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_greater(T t, U u) noexcept -> bool
{
    return cmp_less(u, t);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_less_equal(T t, U u) noexcept -> bool
{
    return !cmp_greater(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(
        detail::int_and_not_char_v<T>&& detail::int_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_greater_equal(T t, U u) noexcept -> bool
{
    return !cmp_less(t, u);
}

/// \brief Returns true if the value of t is in the range of values that can be
/// represented in R, that is, if t can be converted to R without data loss.
///
/// \details It is a compile-time error if either T or R is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type). This function cannot be used with etl::byte, char, char8_t, char16_t,
/// char32_t, wchar_t and bool.
///
/// \notes
/// [cppreference.com/w/cpp/utility/in_range](https://en.cppreference.com/w/cpp/utility/in_range)
template <typename R, typename T, TETL_REQUIRES_(detail::int_and_not_char_v<T>)>
[[nodiscard]] constexpr auto in_range(T t) noexcept -> bool
{
    return etl::cmp_greater_equal(t, etl::numeric_limits<R>::min())
           && etl::cmp_less_equal(t, etl::numeric_limits<R>::max());
}

} // namespace etl

#endif // TETL_DETAIL_UTILITY_CMP_HPP