// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_IS_SORTED_HPP
#define TETL_ALGORITHM_IS_SORTED_HPP

#include <etl/_algorithm/is_sorted_until.hpp>

namespace etl {

/// \brief Checks if the elements in range `[first, last)` are sorted in non-descending order.
/// \ingroup algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted(ForwardIt first, ForwardIt last) -> bool
{
    return etl::is_sorted_until(first, last) == last;
}

/// \ingroup algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted(ForwardIt first, ForwardIt last, Compare comp) -> bool
{
    return etl::is_sorted_until(first, last, comp) == last;
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_SORTED_HPP
