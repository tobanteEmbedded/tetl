// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_FLIP_BIT_HPP
#define TETL_BIT_FLIP_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// Flip bit at position \p pos
/// \note Non-standard extension
/// \ingroup bit-hpp
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto flip_bit(UInt word, UInt pos) noexcept -> UInt
{
    return static_cast<UInt>(word ^ static_cast<UInt>(UInt(1) << pos));
}

/// Flip bit at position Pos
/// \note Non-standard extension
/// \ingroup bit-hpp
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto flip_bit(UInt word) noexcept -> UInt
{
    return etl::flip_bit(word, static_cast<UInt>(Pos));
}

} // namespace etl

#endif // TETL_BIT_FLIP_BIT_HPP
