// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_BIT_BIT_WIDTH_HPP
#define TETL_BIT_BIT_WIDTH_HPP

#include <etl/_bit/countl_zero.hpp>
#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief If x is not zero, calculates the number of bits needed to store the
/// value x, that is, 1+⌊log2(x)⌋. If x is zero, returns zero.
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto bit_width(UInt x) noexcept -> int
{
    return etl::numeric_limits<UInt>::digits - etl::countl_zero(x);
}

} // namespace etl

#endif // TETL_BIT_BIT_WIDTH_HPP
