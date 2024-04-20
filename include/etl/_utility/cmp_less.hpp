// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_CMP_LESS_HPP
#define TETL_UTILITY_CMP_LESS_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_type_traits/is_signed.hpp>
#include <etl/_type_traits/make_unsigned.hpp>

namespace etl {

/// Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
///
/// https://en.cppreference.com/w/cpp/utility/intcmp
///
/// \ingroup utility
template <builtin_integer T, builtin_integer U>
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
