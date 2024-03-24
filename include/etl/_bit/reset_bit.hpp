// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_RESET_BIT_HPP
#define TETL_BIT_RESET_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto reset_bit(UInt val, UInt bit) noexcept -> UInt
{
    return static_cast<UInt>(val & static_cast<UInt>(~(UInt(1) << bit)));
}

template <etl::size_t Bit, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto reset_bit(UInt val) noexcept -> UInt
{
    return etl::reset_bit(val, static_cast<UInt>(Bit));
}

} // namespace etl

#endif // TETL_BIT_RESET_BIT_HPP
