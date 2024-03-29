// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_HAS_SINGLE_BIT_HPP
#define TETL_BIT_HAS_SINGLE_BIT_HPP

#include <etl/_bit/popcount.hpp>
#include <etl/_concepts/builtin_unsigned_integer.hpp>

namespace etl {

/// \brief Checks if x is an integral power of two.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns true if x is an integral power of two; otherwise false.
///
/// \ingroup bit-hpp
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto has_single_bit(UInt x) noexcept -> bool
{
    return etl::popcount(x) == 1;
}

} // namespace etl

#endif // TETL_BIT_HAS_SINGLE_BIT_HPP
