// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_TEST_BIT_HPP
#define TETL_BIT_TEST_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \ingroup bit-hpp
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt val, UInt bit) noexcept -> bool
{
    return static_cast<UInt>(val & static_cast<UInt>(UInt(1) << static_cast<UInt>(bit))) != UInt(0);
}

/// \ingroup bit-hpp
template <etl::size_t Bit, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt val) noexcept -> bool
{
    return etl::test_bit(val, static_cast<UInt>(Bit));
}

} // namespace etl

#endif // TETL_BIT_TEST_BIT_HPP
