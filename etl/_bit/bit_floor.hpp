/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BIT_FLOOR_HPP
#define TETL_BIT_BIT_FLOOR_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief If x is not zero, calculates the largest integral power of two that
/// is not greater than x. If x is zero, returns zero.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns Zero if x is zero; otherwise, the largest integral power of two
/// that is not greater than x.
template <typename T, enable_if_t<detail::bit_uint_v<T>, int> = 0>
[[nodiscard]] constexpr auto bit_floor(T x) noexcept -> T
{
    if (x != 0) { return T { 1U } << (bit_width(x) - 1U); }
    return 0;
}
} // namespace etl

#endif // TETL_BIT_BIT_FLOOR_HPP
