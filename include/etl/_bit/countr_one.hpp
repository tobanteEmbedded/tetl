// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_COUNTR_ONE_HPP
#define TETL_BIT_COUNTR_ONE_HPP

#include <etl/_bit/bit_uint.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Returns the number of consecutive 1 bits in the value of x, starting
/// from the least significant bit ("right").
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 1 bits in the value of x, starting from
/// the least significant bit.
template <detail::bit_uint T>
[[nodiscard]] constexpr auto countr_one(T x) noexcept -> int
{
    auto isBitSet = [](auto val, int pos) -> bool { return val & (T{1} << static_cast<T>(pos)); };

    auto totalBits = numeric_limits<T>::digits;
    auto result    = 0;
    while (result != totalBits) {
        if (!isBitSet(x, result)) {
            break;
        }
        ++result;
    }
    return result;
}

} // namespace etl

#endif // TETL_BIT_COUNTR_ONE_HPP
