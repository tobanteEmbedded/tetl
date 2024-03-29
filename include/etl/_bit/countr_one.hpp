// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_COUNTR_ONE_HPP
#define TETL_BIT_COUNTR_ONE_HPP

#include <etl/_bit/test_bit.hpp>
#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Returns the number of consecutive 1 bits in the value of x, starting
/// from the least significant bit ("right").
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 1 bits in the value of x, starting from
/// the least significant bit.
///
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto countr_one(UInt x) noexcept -> int
{
    auto totalBits = etl::numeric_limits<UInt>::digits;
    auto result    = 0;
    while (result != totalBits) {
        if (not etl::test_bit(x, static_cast<UInt>(result))) {
            break;
        }
        ++result;
    }
    return result;
}

} // namespace etl

#endif // TETL_BIT_COUNTR_ONE_HPP
