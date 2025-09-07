// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_BIT_BIT_CEIL_HPP
#define TETL_BIT_BIT_CEIL_HPP

#include <etl/_bit/bit_width.hpp>
#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Calculates the smallest integral power of two that is not smaller
/// than x. If that value is not representable in UInt, the behavior is undefined.
/// Call to this function is permitted in constant evaluation only if the
/// undefined behavior does not occur.
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The smallest integral power of two that is not smaller than x.
///
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto bit_ceil(UInt x) noexcept -> UInt
{
    if (x <= 1U) {
        return UInt{1};
    }
    if constexpr (is_same_v<UInt, decltype(+x)>) {
        return UInt{1U} << bit_width(UInt{x - 1U});
    } else {
        // for types subject to integral promotion
        auto o = etl::numeric_limits<unsigned>::digits - etl::numeric_limits<UInt>::digits;
        return UInt{1U << (bit_width(UInt{x - 1U}) + o) >> o};
    }
}

} // namespace etl

#endif // TETL_BIT_BIT_CEIL_HPP
