// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_ROTL_HPP
#define TETL_BIT_ROTL_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief Computes the result of bitwise left-rotating the value of x by s
/// positions. This operation is also known as a left circular shift.
template <detail::bit_uint T>
constexpr auto rotl(T t, int s) noexcept -> T
{
    auto const c = static_cast<unsigned>(s);
    auto const d = static_cast<unsigned>(numeric_limits<T>::digits);
    if ((c % d) == 0U) {
        return t;
    }
    return static_cast<T>((t << (c % d)) | (t >> (d - (c % d))));
}

} // namespace etl

#endif // TETL_BIT_ROTL_HPP
