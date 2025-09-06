// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_UTILITY_CMP_LESS_EQUAL_HPP
#define TETL_UTILITY_CMP_LESS_EQUAL_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_utility/cmp_greater.hpp>

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
[[nodiscard]] constexpr auto cmp_less_equal(T t, U u) noexcept -> bool
{
    return not etl::cmp_greater(t, u);
}

} // namespace etl

#endif // TETL_UTILITY_CMP_LESS_EQUAL_HPP
