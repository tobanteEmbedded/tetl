// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_TEST_BIT_HPP
#define TETL_BIT_TEST_BIT_HPP

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// Test bit at position \p pos
/// \details https://stackoverflow.com/questions/47981/how-to-set-clear-and-toggle-a-single-bit
/// \pre Position \p pos must be a valid bit-index for UInt
/// \note Non-standard extension
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt word, UInt pos) noexcept -> bool
{
    TETL_PRECONDITION(static_cast<int>(pos) < etl::numeric_limits<UInt>::digits);
    return static_cast<UInt>(word & static_cast<UInt>(UInt(1) << pos)) != UInt(0);
}

/// Test bit at position `Pos`
/// \details https://stackoverflow.com/questions/47981/how-to-set-clear-and-toggle-a-single-bit
/// \note Non-standard extension
/// \ingroup bit
template <etl::size_t Pos, etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto test_bit(UInt word) noexcept -> bool
{
    static_assert(Pos < etl::numeric_limits<UInt>::digits);
    return etl::test_bit(word, static_cast<UInt>(Pos));
}

} // namespace etl

#endif // TETL_BIT_TEST_BIT_HPP
