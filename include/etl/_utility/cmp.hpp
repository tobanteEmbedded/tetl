// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_CMP_HPP
#define TETL_UTILITY_CMP_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/is_signed.hpp>
#include <etl/_type_traits/make_unsigned.hpp>

namespace etl {

namespace detail {

template <typename T>
concept integer_and_not_char =              //
    etl::is_integral_v<T>                   //
    and (                                   //
        not etl::is_same_v<T, bool>         //
        and not etl::is_same_v<T, char>     //
        and not etl::is_same_v<T, char16_t> //
        and not etl::is_same_v<T, char32_t> //
        and not etl::is_same_v<T, wchar_t>  //
    );

template <typename T, typename U>
concept comparable_integers = integer_and_not_char<T> and integer_and_not_char<U>;

} // namespace detail

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
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
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
[[nodiscard]] constexpr auto cmp_not_equal(T t, U u) noexcept -> bool
{
    return not etl::cmp_equal(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
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
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
[[nodiscard]] constexpr auto cmp_greater(T t, U u) noexcept -> bool
{
    return etl::cmp_less(u, t);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
[[nodiscard]] constexpr auto cmp_less_equal(T t, U u) noexcept -> bool
{
    return not etl::cmp_greater(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// https://en.cppreference.com/w/cpp/utility/intcmp
template <typename T, typename U>
    requires etl::detail::comparable_integers<T, U>
[[nodiscard]] constexpr auto cmp_greater_equal(T t, U u) noexcept -> bool
{
    return not etl::cmp_less(t, u);
}

/// \brief Returns true if the value of t is in the range of values that can be
/// represented in R, that is, if t can be converted to R without data loss.
///
/// \details It is a compile-time error if either T or R is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type). This function cannot be used with etl::byte, char, char8_t, char16_t,
/// char32_t, wchar_t and bool.
///
/// https://en.cppreference.com/w/cpp/utility/in_range
template <typename R, typename T>
    requires etl::detail::integer_and_not_char<T>
[[nodiscard]] constexpr auto in_range(T t) noexcept -> bool
{
    using limits = etl::numeric_limits<R>;
    return etl::cmp_greater_equal(t, limits::min()) and etl::cmp_less_equal(t, limits::max());
}

} // namespace etl

#endif // TETL_UTILITY_CMP_HPP
