// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_ROTR_HPP
#define TETL_BIT_ROTR_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief Computes the result of bitwise right-rotating the value of x by s
/// positions. This operation is also known as a right circular shift.
template <detail::bit_uint T>
constexpr auto rotr(T t, int s) noexcept -> T
{
    auto const cnt    = static_cast<unsigned>(s);
    auto const digits = static_cast<unsigned>(etl::numeric_limits<T>::digits);
    if ((cnt % digits) == 0) {
        return t;
    }
    return (t >> (cnt % digits)) | (t << (digits - (cnt % digits)));
}

} // namespace etl

#endif // TETL_BIT_ROTR_HPP
