/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_POPCOUNT_HPP
#define TETL_BIT_POPCOUNT_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief Returns the number of 1 bits in the value of x.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \module Numeric
template <typename T, enable_if_t<detail::bit_uint_v<T>, int> = 0>
[[nodiscard]] constexpr auto popcount(T input) noexcept -> int
{
    auto count = T { 0 };
    while (input) {
        count = count + (input & T { 1 });
        input = input >> T { 1 };
    }
    return static_cast<int>(count);
}

} // namespace etl

#endif // TETL_BIT_POPCOUNT_HPP