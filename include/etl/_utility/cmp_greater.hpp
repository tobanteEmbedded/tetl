// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_CMP_GREATER_HPP
#define TETL_UTILITY_CMP_GREATER_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_utility/cmp_less.hpp>

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
[[nodiscard]] constexpr auto cmp_greater(T t, U u) noexcept -> bool
{
    return etl::cmp_less(u, t);
}

} // namespace etl

#endif // TETL_UTILITY_CMP_GREATER_HPP
