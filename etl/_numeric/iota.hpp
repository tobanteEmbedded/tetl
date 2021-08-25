/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_IOTA_HPP
#define TETL_NUMERIC_IOTA_HPP

#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief Fills the range [first, last) with sequentially increasing values,
/// starting with value and repetitively evaluating ++value.
/// \group iota
/// \module Algorithm
template <typename ForwardIt, typename T>
constexpr auto iota(ForwardIt first, ForwardIt last, T value) -> void
{
    while (first != last) {
        *first++ = value;
        ++value;
    }
}
} // namespace etl

#endif // TETL_NUMERIC_IOTA_HPP