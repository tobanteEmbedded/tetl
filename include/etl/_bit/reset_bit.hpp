// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_RESET_BIT_HPP
#define TETL_BIT_RESET_BIT_HPP

#include <etl/_concepts/standard_unsigned_integer.hpp>

namespace etl {

template <etl::standard_unsigned_integer UInt>
[[nodiscard]] constexpr auto reset_bit(UInt val, UInt bit) noexcept -> UInt
{
    return static_cast<UInt>(val & static_cast<UInt>(~(UInt(1) << bit)));
}

} // namespace etl

#endif // TETL_BIT_RESET_BIT_HPP
