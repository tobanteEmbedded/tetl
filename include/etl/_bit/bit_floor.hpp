// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_BIT_FLOOR_HPP
#define TETL_BIT_BIT_FLOOR_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"

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
template <detail::bit_uint T>
[[nodiscard]] constexpr auto bit_floor(T x) noexcept -> T
{
    if (x != 0) { return T {1U} << (bit_width(x) - 1U); }
    return 0;
}
} // namespace etl

#endif // TETL_BIT_BIT_FLOOR_HPP
