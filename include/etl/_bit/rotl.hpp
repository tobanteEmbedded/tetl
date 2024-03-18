// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_ROTL_HPP
#define TETL_BIT_ROTL_HPP

#include <etl/_concepts/standard_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Computes the result of bitwise left-rotating the value of x by s
/// positions. This operation is also known as a left circular shift.
template <etl::standard_unsigned_integer UInt>
constexpr auto rotl(UInt t, int s) noexcept -> UInt
{
    auto const c = static_cast<unsigned>(s);
    auto const d = static_cast<unsigned>(etl::numeric_limits<UInt>::digits);
    if ((c % d) == 0U) {
        return t;
    }
    return static_cast<UInt>((t << (c % d)) | (t >> (d - (c % d))));
}

} // namespace etl

#endif // TETL_BIT_ROTL_HPP
