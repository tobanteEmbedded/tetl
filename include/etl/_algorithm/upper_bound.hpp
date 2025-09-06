// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_UPPER_BOUND_HPP
#define TETL_ALGORITHM_UPPER_BOUND_HPP

#include <etl/_functional/less.hpp>
#include <etl/_iterator/advance.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Returns an iterator pointing to the first element in the range `[first, last)`
/// that is greater than `value`, or last if no such element is found.
///
/// The range `[first, last)` must be partitioned with respect to the
/// expression `not (value < element)` or `not comp(value, element)`, i.e., all
/// elements for which the expression is true must precede all elements for
/// which the expression is false. A fully-sorted range meets this criterion.
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto upper_bound(ForwardIt first, ForwardIt last, T const& value, Compare comp) -> ForwardIt
{
    auto count = etl::distance(first, last);
    while (count > 0) {
        auto it   = first;
        auto step = count / 2;
        etl::advance(it, step);
        if (not comp(value, *it)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto upper_bound(ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return etl::upper_bound(first, last, value, etl::less());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_UPPER_BOUND_HPP
