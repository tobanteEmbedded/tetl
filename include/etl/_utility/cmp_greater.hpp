// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_CMP_GREATER_HPP
#define TETL_UTILITY_CMP_GREATER_HPP

#include <etl/_utility/cmp_less.hpp>
#include <etl/_utility/comparable_integers.hpp>

namespace etl {

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

} // namespace etl

#endif // TETL_UTILITY_CMP_GREATER_HPP
