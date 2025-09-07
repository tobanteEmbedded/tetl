// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch
#ifndef TETL_NUMERIC_IOTA_HPP
#define TETL_NUMERIC_IOTA_HPP

#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Fills the range [first, last) with sequentially increasing values,
/// starting with value and repetitively evaluating ++value.
/// \ingroup numeric
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
