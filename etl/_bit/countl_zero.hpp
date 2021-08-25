/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_COUNTL_ZERO_HPP
#define TETL_BIT_COUNTL_ZERO_HPP

#include "etl/_bit/bit_unsigned_int.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief Returns the number of consecutive 0 bits in the value of x, starting
/// from the most significant bit ("left").
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns The number of consecutive 0 bits in the value of x, starting from
/// the most significant bit.
/// \module Numeric
template <typename T>
[[nodiscard]] constexpr auto countl_zero(T x) noexcept
    -> enable_if_t<detail::bit_unsigned_int_v<T>, int>
{
    auto const totalBits = etl::numeric_limits<T>::digits;
    if (x == T(0)) { return etl::numeric_limits<T>::digits; }

    auto res = 0;
    while (!(x & (T(1) << (static_cast<T>(totalBits) - T(1))))) {
        x = static_cast<T>(x << T(1));
        ++res;
    }

    return res;
}

} // namespace etl

#endif // TETL_BIT_COUNTL_ZERO_HPP