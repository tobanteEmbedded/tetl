/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BIT_WIDTH_HPP
#define TETL_BIT_BIT_WIDTH_HPP

#include "etl/_bit/bit_unsigned_int.hpp"
#include "etl/_bit/countl_zero.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief If x is not zero, calculates the number of bits needed to store the
/// value x, that is, 1+⌊log2(x)⌋. If x is zero, returns zero.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
/// \module Numeric
template <typename T, enable_if_t<detail::bit_unsigned_int_v<T>, int> = 0>
[[nodiscard]] constexpr auto bit_width(T x) noexcept -> int
{
    return etl::numeric_limits<T>::digits - etl::countl_zero(x);
}

} // namespace etl

#endif // TETL_BIT_BIT_WIDTH_HPP