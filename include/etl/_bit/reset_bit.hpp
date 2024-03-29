// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_RESET_BIT_HPP
#define TETL_BIT_RESET_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// Reset bit at position \p pos
/// \note Non-standard extension
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto reset_bit(UInt word, UInt pos) noexcept -> UInt
{
    return static_cast<UInt>(word & static_cast<UInt>(~(UInt(1) << pos)));
}

/// Reset bit at position Pos
/// \note Non-standard extension
/// \ingroup bit
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto reset_bit(UInt word) noexcept -> UInt
{
    return etl::reset_bit(word, static_cast<UInt>(Pos));
}

} // namespace etl

#endif // TETL_BIT_RESET_BIT_HPP
