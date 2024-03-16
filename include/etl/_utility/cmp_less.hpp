// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_CMP_LESS_HPP
#define TETL_UTILITY_CMP_LESS_HPP

#include <etl/_type_traits/is_signed.hpp>
#include <etl/_type_traits/make_unsigned.hpp>
#include <etl/_utility/comparable_integers.hpp>

namespace etl {

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
///
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer type).
///
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

} // namespace etl

#endif // TETL_UTILITY_CMP_LESS_HPP
