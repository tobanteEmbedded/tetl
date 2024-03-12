// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_BIT_CEIL_HPP
#define TETL_BIT_BIT_CEIL_HPP

#include <etl/_bit/bit_uint.hpp>
#include <etl/_bit/bit_width.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Calculates the smallest integral power of two that is not smaller
/// than x. If that value is not representable in T, the behavior is undefined.
/// Call to this function is permitted in constant evaluation only if the
/// undefined behavior does not occur.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The smallest integral power of two that is not smaller than x.
template <detail::bit_uint T>
[[nodiscard]] constexpr auto bit_ceil(T x) noexcept -> T
{
    if (x <= 1U) {
        return T{1};
    }
    if constexpr (is_same_v<T, decltype(+x)>) {
        return T{1U} << bit_width(T{x - 1U});
    } else {
        // for types subject to integral promotion
        auto o = numeric_limits<unsigned>::digits - numeric_limits<T>::digits;
        return T{1U << (bit_width(T{x - 1U}) + o) >> o};
    }
}

} // namespace etl

#endif // TETL_BIT_BIT_CEIL_HPP
