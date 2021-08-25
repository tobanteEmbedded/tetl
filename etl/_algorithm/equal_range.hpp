/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_EQUAL_RANGE_HPP
#define TETL_ALGORITHM_EQUAL_RANGE_HPP

#include "etl/_algorithm/lower_bound.hpp"
#include "etl/_algorithm/upper_bound.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Returns a range containing all elements equivalent to value in the
/// range `[first, last)`.
///
/// https://en.cppreference.com/w/cpp/algorithm/equal_range
///
/// \group equal_range
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    return make_pair(lower_bound(first, last, value, comp),
        upper_bound(first, last, value, comp));
}

/// \group equal_range
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value) -> pair<ForwardIt, ForwardIt>
{
    return equal_range(first, last, value, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_RANGE_HPP