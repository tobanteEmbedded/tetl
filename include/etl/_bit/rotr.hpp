// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_ROTR_HPP
#define TETL_BIT_ROTR_HPP

#include <etl/_concepts/standard_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Computes the result of bitwise right-rotating the value of x by s
/// positions. This operation is also known as a right circular shift.
template <etl::standard_unsigned_integer UInt>
constexpr auto rotr(UInt t, int s) noexcept -> UInt
{
    auto const cnt    = static_cast<unsigned>(s);
    auto const digits = static_cast<unsigned>(etl::numeric_limits<UInt>::digits);
    if ((cnt % digits) == 0) {
        return t;
    }
    return static_cast<UInt>((t >> (cnt % digits)) | (t << (digits - (cnt % digits))));
}

} // namespace etl

#endif // TETL_BIT_ROTR_HPP
