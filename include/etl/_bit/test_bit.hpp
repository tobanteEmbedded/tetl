// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_TEST_BIT_HPP
#define TETL_BIT_TEST_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// Test bit at position \p pos
/// \note Non-standard extension
/// \ingroup bit-hpp
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt word, UInt pos) noexcept -> bool
{
    return static_cast<UInt>(word & static_cast<UInt>(UInt(1) << pos)) != UInt(0);
}

/// Test bit at position `Pos`
/// \note Non-standard extension
/// \ingroup bit-hpp
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt word) noexcept -> bool
{
    return etl::test_bit(word, static_cast<UInt>(Pos));
}

} // namespace etl

#endif // TETL_BIT_TEST_BIT_HPP
