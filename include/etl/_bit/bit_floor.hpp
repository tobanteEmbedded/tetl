// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_BIT_FLOOR_HPP
#define TETL_BIT_BIT_FLOOR_HPP

#include <etl/_bit/bit_width.hpp>
#include <etl/_concepts/standard_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief If x is not zero, calculates the largest integral power of two that
/// is not greater than x. If x is zero, returns zero.
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns Zero if x is zero; otherwise, the largest integral power of two
/// that is not greater than x.
template <etl::standard_unsigned_integer UInt>
[[nodiscard]] constexpr auto bit_floor(UInt x) noexcept -> UInt
{
    if (x != 0) {
        return UInt(1) << (static_cast<UInt>(etl::bit_width(x)) - UInt(1));
    }
    return 0;
}
} // namespace etl

#endif // TETL_BIT_BIT_FLOOR_HPP
