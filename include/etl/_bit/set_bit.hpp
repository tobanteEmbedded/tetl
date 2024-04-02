// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_SET_BIT_HPP
#define TETL_BIT_SET_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// Set bit at position \p pos
/// \note Non-standard extension
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto set_bit(UInt word, UInt pos) noexcept -> UInt
{
    return static_cast<UInt>(word | static_cast<UInt>(UInt(1) << pos));
}

/// Set bit at position \p pos to \p value
/// \note Non-standard extension
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto set_bit(UInt word, UInt pos, bool value) -> UInt
{
    return static_cast<UInt>((word & static_cast<UInt>(~(UInt(1) << pos))) | (UInt(value) << pos));
}

/// Set bit at position `Pos`
/// \note Non-standard extension
/// \ingroup bit
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto set_bit(UInt word) noexcept -> UInt
{
    return etl::set_bit(word, static_cast<UInt>(Pos));
}

/// Set bit at position `Pos` to \p value
/// \note Non-standard extension
/// \ingroup bit
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto set_bit(UInt word, bool value) noexcept -> UInt
{
    return etl::set_bit(word, static_cast<UInt>(Pos), value);
}

} // namespace etl

#endif // TETL_BIT_SET_BIT_HPP
