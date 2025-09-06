// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_EQUAL_RANGE_HPP
#define TETL_ALGORITHM_EQUAL_RANGE_HPP

#include <etl/_algorithm/lower_bound.hpp>
#include <etl/_algorithm/upper_bound.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief Returns a range containing all elements equivalent to value in the
/// range `[first, last)`.
///
/// https://en.cppreference.com/w/cpp/algorithm/equal_range
///
/// \ingroup algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last, T const& value, Compare comp)
    -> pair<ForwardIt, ForwardIt>
{
    return etl::make_pair(etl::lower_bound(first, last, value, comp), etl::upper_bound(first, last, value, comp));
}

/// \ingroup algorithm
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last, T const& value) -> pair<ForwardIt, ForwardIt>
{
    return etl::equal_range(first, last, value, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_RANGE_HPP
