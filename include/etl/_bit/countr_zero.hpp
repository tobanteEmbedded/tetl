// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_COUNTR_ZERO_HPP
#define TETL_BIT_COUNTR_ZERO_HPP

#include <etl/_concepts/standard_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Returns the number of consecutive 0 bits in the value of x, starting
/// from the least significant bit ("right").
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 0 bits in the value of x, starting from
/// the least significant bit.
template <etl::standard_unsigned_integer UInt>
[[nodiscard]] constexpr auto countr_zero(UInt x) noexcept -> int
{
    auto isBitSet = [](auto val, int pos) -> bool { return val & (UInt{1} << static_cast<UInt>(pos)); };

    auto totalBits = etl::numeric_limits<UInt>::digits;
    auto result    = 0;
    while (result != totalBits) {
        if (isBitSet(x, result)) {
            break;
        }
        ++result;
    }
    return result;
}

} // namespace etl

#endif // TETL_BIT_COUNTR_ZERO_HPP
