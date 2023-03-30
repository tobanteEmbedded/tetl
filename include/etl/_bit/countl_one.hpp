// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_COUNTL_ONE_HPP
#define TETL_BIT_COUNTL_ONE_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief Returns the number of consecutive 1 ("one") bits in the value of x,
/// starting from the most significant bit ("left").
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 1 bits in the value of x, starting from
/// the most significant bit.
template <detail::bit_uint T>
[[nodiscard]] constexpr auto countl_one(T x) noexcept -> int
{
    auto const totalBits = etl::numeric_limits<T>::digits;
    if (x == etl::numeric_limits<T>::max()) { return totalBits; }

    auto res = 0;
    while (x & (T(1) << (static_cast<T>(totalBits) - T(1)))) {
        x = static_cast<T>(x << T(1));
        ++res;
    }

    return res;
}

} // namespace etl

#endif // TETL_BIT_COUNTL_ONE_HPP
