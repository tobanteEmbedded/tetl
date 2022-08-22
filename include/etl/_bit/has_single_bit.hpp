/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_HAS_SINGLE_BIT_HPP
#define TETL_BIT_HAS_SINGLE_BIT_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_bit/popcount.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief Checks if x is an integral power of two.
///
/// \details This overload only participates in overload resolution if T is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \returns true if x is an integral power of two; otherwise false.
template <typename T, enable_if_t<detail::bit_uint_v<T>, int> = 0>
[[nodiscard]] constexpr auto has_single_bit(T x) noexcept -> bool
{
    return popcount(x) == 1;
}

} // namespace etl

#endif // TETL_BIT_HAS_SINGLE_BIT_HPP
