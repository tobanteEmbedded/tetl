// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_COUNTL_ONE_HPP
#define TETL_BIT_COUNTL_ONE_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Returns the number of consecutive 1 ("one") bits in the value of x,
/// starting from the most significant bit ("left").
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 1 bits in the value of x, starting from
/// the most significant bit.
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto countl_one(UInt x) noexcept -> int
{
    auto const totalBits = etl::numeric_limits<UInt>::digits;
    if (x == etl::numeric_limits<UInt>::max()) {
        return totalBits;
    }

    auto res = 0;
    while (x & (UInt(1) << (static_cast<UInt>(totalBits) - UInt(1)))) {
        x = static_cast<UInt>(x << UInt(1));
        ++res;
    }

    return res;
}

} // namespace etl

#endif // TETL_BIT_COUNTL_ONE_HPP
